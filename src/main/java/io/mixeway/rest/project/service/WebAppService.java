package io.mixeway.rest.project.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.webappscan.WebAppScanClient;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.rest.project.model.RunScanForWebApps;
import io.mixeway.rest.project.model.WebAppCard;
import io.mixeway.rest.project.model.WebAppModel;
import io.mixeway.rest.project.model.WebAppPutModel;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.postgresql.util.PSQLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.pojo.Status;

import java.security.Principal;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class WebAppService {
    private static final Logger log = LoggerFactory.getLogger(WebAppService.class);
    private final WebAppRepository webAppRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final ScannerRepository scannerRepository;
    private final ProjectRepository projectRepository;
    private final WebAppHeaderRepository webAppHeaderRepository;
    private final WebAppScanRepository webAppScanRepository;
    private final WebAppVulnRepository webAppVulnRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final List<WebAppScanClient> webAppScanClients;
    private final PermissionFactory permissionFactory;

    @Autowired
    WebAppService(WebAppRepository webAppRepository, ScannerTypeRepository scannerTypeRepository, List<WebAppScanClient> webAppScanClients,
                  ScannerRepository scannerRepository, ProjectRepository projectRepository, WebAppHeaderRepository webAppHeaderRepository,
                  WebAppScanRepository webAppScanRepository, WebAppVulnRepository webAppVulnRepository, ProjectRiskAnalyzer projectRiskAnalyzer,
                  PermissionFactory permissionFactory){
        this.webAppHeaderRepository = webAppHeaderRepository;
        this.webAppRepository = webAppRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.scannerRepository = scannerRepository;
        this.projectRepository = projectRepository;
        this.webAppScanRepository = webAppScanRepository;
        this.permissionFactory = permissionFactory;
        this.webAppVulnRepository = webAppVulnRepository;
        this.webAppScanClients = webAppScanClients;
        this.projectRiskAnalyzer = projectRiskAnalyzer;
    }



    public ResponseEntity<Status> runSingleWebApp(Long webAppId, String username) {
        try {
            Optional<Scanner> scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_ACUNETIX)).stream().findFirst();
            Optional<WebApp> webApp = webAppRepository.findById(webAppId);
            if (webApp.isPresent() && scanner.isPresent() ) {
                for (WebAppScanClient webAppScanClient : webAppScanClients){
                    if (webAppScanClient.canProcessRequest(scanner.get())){
                        webAppScanClient.runScan(webApp.get(),scanner.get());
                    }
                }
            }
        } catch (Exception e){
            return new ResponseEntity<>(null, HttpStatus.EXPECTATION_FAILED);
        }
        log.info("{} - Started scan of webapps - scope single", username);
        return new ResponseEntity<>(null,HttpStatus.CREATED);
    }

    public ResponseEntity<Status> deleteWebApp(Long webAppId, String username) {
        Optional<WebApp> webApp = webAppRepository.findById(webAppId);
        if (webApp.isPresent() ) {
            webAppRepository.delete(webApp.get());
            log.info("{} - Deleted webapp  {}", username, webApp.get().getUrl());
            return new ResponseEntity<>(null,HttpStatus.OK);
        }
        return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
    }
    public ResponseEntity<Status> runAllScanForWebApp(Long id, String username) {
        Optional<Project> project = projectRepository.findById(id);
        Optional<Scanner> scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_ACUNETIX)).stream().findFirst();
        if (project.isPresent() && scanner.isPresent()){
            //AddTarget
            try {
                for (WebApp webApp : project.get().getWebapps()) {
                    webApp.setInQueue(true);
                    webAppRepository.save(webApp);
                }
            } catch (Exception e) {
                return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
            }
            log.info("{} - Started scan of webapps for project {} - scope full", username, project.get().getName());
            return new ResponseEntity<>(null,HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> runSelectedWebApps(Long id, List<RunScanForWebApps> runScanForWebApps, String username) {
        Optional<Project> project = projectRepository.findById(id);
        Optional<Scanner> scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_ACUNETIX)).stream().findFirst();

        if (project.isPresent() && scanner.isPresent()){

            for (RunScanForWebApps selectedApp : runScanForWebApps){
                try{
                    Optional<WebApp> webApp = webAppRepository.findById(selectedApp.getWebAppId());
                    if (webApp.isPresent() && webApp.get().getProject() == project.get()){
                        for (WebAppScanClient webAppScanClient : webAppScanClients){
                            if (webAppScanClient.canProcessRequest(scanner.get())){
                                webAppScanClient.runScan(webApp.get(),scanner.get());
                            }
                        }
                    }
                } catch (Exception e){
                    return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
                }
            }
            log.info("{} - Started scan of webapps for project {} - scope partial", username, project.get().getName());
            return new ResponseEntity<>(null,HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<Status> saveWebApp(Long id, WebAppPutModel webAppPutMode, String usernamel) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()) {
            try {
                WebApp webApp = new WebApp();
                webApp.setUrl(webAppPutMode.getWebAppUrl());
                webApp.setRunning(false);
                webApp.setPublicscan(webAppPutMode.isScanPublic());
                webApp.setProject(projectRepository.getOne(id));
                webAppRepository.save(webApp);
                for (String header : webAppPutMode.getWebAppHeaders().split(",")) {
                    String[] headerValues = header.split(":");
                    if (headerValues.length == 2) {
                        WebAppHeader waHeader = new WebAppHeader();
                        waHeader.setHeaderName(headerValues[0]);
                        waHeader.setHeaderValue(headerValues[1]);
                        waHeader.setWebApp(webApp);
                        webAppHeaderRepository.save(waHeader);
                    }
                }
                log.info("{} - Added webapp [{}] {} and set {} headers", usernamel, project.get().getName(), webApp.getUrl(), webApp.getHeaders() != null ? webApp.getHeaders().size() : 0);
                return new ResponseEntity<>(null, HttpStatus.CREATED);
            } catch (DataIntegrityViolationException ex) {
                log.info("{} - is trying to add duplicate URL [{}] for project {} ", usernamel, LogUtil.prepare(webAppPutMode.getWebAppUrl()), project.get().getName());
                return new ResponseEntity<>(null, HttpStatus.CONFLICT);
            }
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> enableWebAppAutoScan(Long id, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            List<Scanner> scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_ACUNETIX));
            WebAppScan webAppScan = new WebAppScan();
            webAppScan.setProject(project.get());
            webAppScan.setScanner(scanner.get(0));
            webAppScan.setType("auto");
            webAppScan.setRunning(false);
            webAppScanRepository.save(webAppScan);
            project.get().setAutoWebAppScan(true);
            project.get().setWebAppAutoDiscover(true);
            projectRepository.save(project.get());
            log.info("{} - Enabled auto webapp scan for project {}", username, project.get().getName());
            return new ResponseEntity<>(null,HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<List<WebAppVuln>> showWebAppVulns(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Set<WebAppVuln> appVulns = webAppVulnRepository.findByWebAppInAndSeverityNot(project.get().getWebapps(),Constants.INFO_SEVERITY);
            return new ResponseEntity<>(new ArrayList<>(appVulns),HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<WebAppCard> showWebApps(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if ( project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            WebAppCard webAppCard = new WebAppCard();
            List<WebAppModel> webAppModels = new ArrayList<>();
            webAppCard.setWebAppAutoScan(project.get().isAutoWebAppScan());
            for (WebApp wa : project.get().getWebapps()){
                WebAppModel webAppModel = new WebAppModel();
                webAppModel.setPublicScan(wa.getPublicscan()!=null ? wa.getPublicscan() : false);
                webAppModel.setWebAppId(wa.getId());
                webAppModel.setRunning(wa.getRunning());
                webAppModel.setUrl(wa.getUrl());
                int risk = projectRiskAnalyzer.getWebAppRisk(wa);
                webAppModel.setRisk(Math.min(risk, 100));
                webAppModels.add(webAppModel);
            }
            webAppCard.setWebAppModels(webAppModels);
            return new ResponseEntity<>(webAppCard,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> disableWebAppAutoScan(Long id, String name) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            project.get().setAutoWebAppScan(false);
            project.get().setWebAppAutoDiscover(false);
            projectRepository.save(project.get());
            log.info("{} - Disabled auto webapp scan for project {}", name, project.get().getName());
            return new ResponseEntity<>(null,HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
}
