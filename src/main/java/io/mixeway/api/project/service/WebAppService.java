package io.mixeway.api.project.service;

import io.mixeway.api.project.model.WebAppCard;
import io.mixeway.api.project.model.WebAppModel;
import io.mixeway.api.project.model.WebAppPutModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.WebApp;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.UpdateProjectService;
import io.mixeway.domain.service.scanmanager.webapp.DeleteWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.GetOrCreateWebAppService;
import io.mixeway.domain.service.scanner.FindScannerService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.service.webapp.WebAppScanService;
import io.mixeway.utils.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Log4j2
public class WebAppService {

    private final WebAppScanService webAppScanService;
    private final PermissionFactory permissionFactory;
    private final VulnTemplate vulnTemplate;
    private final FindWebAppService findWebAppService;
    private final DeleteWebAppService deleteWebAppService;
    private final FindProjectService findProjectService;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final UpdateProjectService updateProjectService;

    private List<String> logs = new ArrayList<String>(){{
        add(Constants.LOG_SEVERITY);
        add(Constants.INFO_SEVERITY);
    }};



    public ResponseEntity<Status> runSingleWebApp(Long webAppId, Principal principal) {
        return webAppScanService.putSingleWebAppToQueue(webAppId, principal);
    }

    public ResponseEntity<Status> deleteWebApp(Long webAppId, Principal principal) {
        Optional<WebApp> webApp = findWebAppService.findById(webAppId);
        if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
            deleteWebAppService.delete(webApp.get());
            log.info("{} - Deleted webapp  {}", principal.getName(), webApp.get().getUrl());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }
    public ResponseEntity<Status> runAllScanForWebApp(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        boolean error = false;
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get()) ){
            try {
                for (WebApp webApp : project.get().getWebapps()) {
                    if (!webAppScanService.putSingleWebAppToQueue(webApp.getId(), principal).getStatusCode().equals(HttpStatus.CREATED))
                        error = true;
                }
            } catch (Exception e) {
                e.printStackTrace();
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
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            try {
                WebApp webApp = getOrCreateWebAppService.createWebApp(project.get(), webAppPutMode);

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
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            updateProjectService.enableWebAppAutoScan(project.get());
            log.info("{} - Enabled auto webapp scan for project {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<List<ProjectVulnerability>> showWebAppVulns(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            List<ProjectVulnerability> appVulns = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectAndVulnerabilitySourceAndSeverityNotIn(project.get(), vulnTemplate.SOURCE_WEBAPP,logs);
            return new ResponseEntity<>(new ArrayList<>(appVulns),HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<WebAppCard> showWebApps(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
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
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            updateProjectService.disableWebAppAutoScan(project.get());
            log.info("{} - Disabled auto webapp scan for project {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
}
