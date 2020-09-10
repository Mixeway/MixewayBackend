package io.mixeway.rest.project.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.webappscan.service.WebAppScanService;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.project.model.RunScanForWebApps;
import io.mixeway.rest.project.model.WebAppCard;
import io.mixeway.rest.project.model.WebAppModel;
import io.mixeway.rest.project.model.WebAppPutModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.pojo.Status;

import java.security.Principal;
import java.util.*;

@Service
public class WebAppService {
    private static final Logger log = LoggerFactory.getLogger(WebAppService.class);
    private final WebAppRepository webAppRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final ScannerRepository scannerRepository;
    private final ProjectRepository projectRepository;
    private final WebAppHeaderRepository webAppHeaderRepository;
    private final WebAppScanRepository webAppScanRepository;
    private final WebAppScanService webAppScanService;
    private final PermissionFactory permissionFactory;
    private final RoutingDomainRepository routingDomainRepository;
    private final VaultHelper vaultHelper;
    private final VulnTemplate vulnTemplate;
    private List<String> logs = new ArrayList<String>(){{
        add(Constants.LOG_SEVERITY);
        add(Constants.INFO_SEVERITY);
    }};
    WebAppService(WebAppRepository webAppRepository, ScannerTypeRepository scannerTypeRepository, WebAppScanService webAppScanService,
                  ScannerRepository scannerRepository, ProjectRepository projectRepository, WebAppHeaderRepository webAppHeaderRepository,
                  WebAppScanRepository webAppScanRepository, VulnTemplate vulnTemplate,
                  PermissionFactory permissionFactory, RoutingDomainRepository routingDomainRepository,
                  VaultHelper vaultHelper){
        this.webAppHeaderRepository = webAppHeaderRepository;
        this.webAppRepository = webAppRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.scannerRepository = scannerRepository;
        this.projectRepository = projectRepository;
        this.vaultHelper =vaultHelper;
        this.webAppScanRepository = webAppScanRepository;
        this.permissionFactory = permissionFactory;
        this.vulnTemplate = vulnTemplate;
        this.webAppScanService = webAppScanService;
        this.routingDomainRepository = routingDomainRepository;
    }



    public ResponseEntity<Status> runSingleWebApp(Long webAppId, Principal principal) {
        return webAppScanService.putSingleWebAppToQueue(webAppId, principal);
    }

    public ResponseEntity<Status> deleteWebApp(Long webAppId, Principal principal) {
        Optional<WebApp> webApp = webAppRepository.findById(webAppId);
        if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
            webAppRepository.delete(webApp.get());
            log.info("{} - Deleted webapp  {}", principal.getName(), webApp.get().getUrl());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }
    public ResponseEntity<Status> runAllScanForWebApp(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        boolean error = false;
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get()) ){
            try {
                for (WebApp webApp : project.get().getWebapps()) {
                    if (!webAppScanService.putSingleWebAppToQueue(webApp.getId(), principal).getStatusCode().equals(HttpStatus.CREATED))
                        error = true;
                }
            } catch (Exception e) {
                return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
            }
            if (!error) {
                log.info("{} - Started scan of webapps for project {} - scope full", principal.getName(), project.get().getName());
                return new ResponseEntity<>(HttpStatus.CREATED);
            }
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> runSelectedWebApps(Long id, List<RunScanForWebApps> runScanForWebApps, Principal principal) {
        return webAppScanService.putSelectedWebAppsToQueue(id, runScanForWebApps,principal);
    }
    public ResponseEntity<Status> saveWebApp(Long id, WebAppPutModel webAppPutMode, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            try {
                WebApp webApp = new WebApp();
                webApp.setUrl(webAppPutMode.getWebAppUrl());
                webApp.setRunning(false);
                webApp.setInQueue(false);
                webApp.setAppClient(webAppPutMode.getAppClient());
                webApp.setRoutingDomain(routingDomainRepository.getOne(webAppPutMode.getRoutingDomainForAsset()));
                webApp.setOrigin(Constants.STRATEGY_GUI);
                webApp.setPublicscan(webAppPutMode.isScanPublic());
                webApp.setProject(projectRepository.getOne(id));
                if (webAppPutMode.isPasswordAuthSet()){
                    webApp.setUsername(webAppPutMode.getWebAppUsername());
                    String uuidToken = UUID.randomUUID().toString();
                    if (vaultHelper.savePassword(webAppPutMode.getWebAppPassword(), uuidToken)){
                        webApp.setPassword(uuidToken);
                    } else {
                        webApp.setPassword(webAppPutMode.getWebAppPassword());
                    }
                }
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
                log.info("{} - Added webapp [{}] {} and set {} headers", principal.getName(), project.get().getName(), webApp.getUrl(), webApp.getHeaders() != null ? webApp.getHeaders().size() : 0);
                return new ResponseEntity<>(HttpStatus.CREATED);
            } catch (DataIntegrityViolationException ex) {
                log.info("{} - is trying to add duplicate URL [{}] for project {} ", principal.getName(), LogUtil.prepare(webAppPutMode.getWebAppUrl()), project.get().getName());
                return new ResponseEntity<>(HttpStatus.CONFLICT);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> enableWebAppAutoScan(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
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
            log.info("{} - Enabled auto webapp scan for project {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<List<ProjectVulnerability>> showWebAppVulns(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            List<ProjectVulnerability> appVulns = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectAndVulnerabilitySourceAndSeverityNotIn(project.get(), vulnTemplate.SOURCE_WEBAPP,logs);
            return new ResponseEntity<>(new ArrayList<>(appVulns),HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
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
                webAppModel.setRoutingDomain(wa.getRoutingDomain());
                webAppModel.setRunning(wa.getRunning());
                webAppModel.setUrl(wa.getUrl());
                webAppModel.setInQueue(wa.getInQueue());
                webAppModel.setRisk(wa.getRisk());
                webAppModels.add(webAppModel);
            }
            webAppCard.setWebAppModels(webAppModels);
            return new ResponseEntity<>(webAppCard,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> disableWebAppAutoScan(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            project.get().setAutoWebAppScan(false);
            project.get().setWebAppAutoDiscover(false);
            projectRepository.save(project.get());
            log.info("{} - Disabled auto webapp scan for project {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
}
