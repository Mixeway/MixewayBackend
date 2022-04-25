package io.mixeway.scanmanager.service.webapp;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.projectvulnerability.GetProjectVulnerabilitiesService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.GetOrCreateWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.UpdateWebAppService;
import io.mixeway.domain.service.scanner.GetScannerService;
import io.mixeway.domain.service.scanner.UpdateScannerService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.model.WebAppScanModel;
import io.mixeway.utils.*;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;

import java.security.Principal;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Service
@Log4j2
@RequiredArgsConstructor
public class WebAppScanService {
    private final List<WebAppScanClient> webAppScanClients;
    private final VulnTemplate vulnTemplate;
    private final PermissionFactory permissionFactory;
    private final FindProjectService findProjectService;
    private final UpdateWebAppService updateWebAppService;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final FindWebAppService findWebAppService;
    private final GetScannerService getScannerService;
    private final GetProjectVulnerabilitiesService getProjectVulnerabilitiesService;
    private final UpdateScannerService updateScannerService;

    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");



    /**
     * Method which is processing webapp from REST API to create or update and put in queue.
     * It verify if there are number of patterns in URL to detect possible duplicates. For example urls which are different from each other
     * only by UUID. If there is no duplicate webapp is created. If duplicate is detected all headers and cookies are updated.
     * in the end application is put into scan queue.
     *
     * @param id of a project to link with webapp
     * @param webAppScanModelList model of app to create/update and scan
     * @param origin place which execute method. Necessary for Scan Strategy.
     * @return entity with status CREATED when scan is created, NOT_FOUND when there is no project and PRECONDITION_FAILED when duplicate detected
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ResponseEntity<Status> processScanWebAppRequest(Long id, List<WebAppScanModel> webAppScanModelList, String origin, Principal principal) {
        synchronized (this) {
            String requestId = UUID.randomUUID().toString();
            Optional<Project> project = findProjectService.findProjectById(id);
            try {
                if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
                    for (WebAppScanModel webAppScanModel : webAppScanModelList) {
                        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp(webAppScanModel.getUrl(), project.get(),webAppScanModel,origin,requestId);
                        updateWebAppService.updateAndPutWebAppToQueue(webApp,webAppScanModel,requestId,true);
                        //updateWebAppService.setCodeProjectLink(webApp,project.get(),webAppScanModel);
                        log.info("WebApp {} in project {} added to queue", webApp.getUrl(), project.get().getName());
                    }
                    return new ResponseEntity<>(new Status("Scan is requested", requestId), HttpStatus.CREATED);
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
            } catch(Exception e){
                log.error("Problem occured during procesing web app scan request for project {} by {}", id, principal.getName());
                return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
            }

        }
    }

    /**
     * Finding WebApp with Runninng= true and check if scan is ended
     * then it decrease number of running scan for particular scanner
     *
     * @throws Exception
     */
    @Transactional
    public void scheduledCheckAndDownloadResults() throws Exception {
        List<WebApp> apps = findWebAppService.findRunningWebApps();
        for (WebApp app : apps) {
            Scanner scanner = getScannerService.getScannerForWebApp(app);
            try {
                if (scanner != null ) {
                    for (WebAppScanClient webAppScanClient : webAppScanClients) {
                        if (webAppScanClient.canProcessRequest(scanner) && webAppScanClient.isScanDone(scanner, app)) {
                            log.info("[WebAppScan] Scan for {} is done.", app.getUrl());
                            List<ProjectVulnerability> tmpVulns = getProjectVulnerabilitiesService.getProjectVulnerabilitiesForSource(app, null);
                            if (tmpVulns.size() > 0) {
                                vulnTemplate.projectVulnerabilityRepository.updateVulnState(tmpVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList()),
                                        vulnTemplate.STATUS_REMOVED.getId());
                                tmpVulns.forEach(v -> v.setStatus(vulnTemplate.STATUS_REMOVED));
                            }
                            //vulnTemplate.projectVulnerabilityRepository.deleteByWebApp(app);
                            webAppScanClient.loadVulnerabilities(scanner,app, null, tmpVulns);
                            updateScannerService.decreaseScanNumber(scanner);
                            updateWebAppService.updateRisk(app);
                            vulnTemplate.projectVulnerabilityRepository.deleteByStatus(vulnTemplate.STATUS_REMOVED);
                            break;
                        }
                    }
                }
            } catch (HttpClientErrorException e) {
                if (e.getRawStatusCode() == 404) {
                    updateWebAppService.endScan(app);
                    updateScannerService.decreaseScanNumber(scanner);
                    log.warn("WebApp deleted manualy from scanner - {} {}", e.getRawStatusCode(), app.getUrl());
                } else {
                    updateWebAppService.endScan(app);
                    updateScannerService.decreaseScanNumber(scanner);
                    log.warn("HttpClientException with code {} for webapp {}", e.getRawStatusCode(), app.getUrl());
                }
            }
        }
    }

    /**
     * Method which takes WebApps with inQueue = true
     * Check if Scanner for particular App is limit free and then run the scan for this app.
     * If Limit is exceeded webapp is left inqueue
     *
     */
    @Transactional
    public void scheduledRunWebAppScanFromQueue() throws Exception {
        List<WebApp> webApps = findWebAppService.findInQueueWebApps();
        for (WebApp webApp : webApps){
            Scanner scanner = getScannerService.getScannerForWebApp(webApp);
            if (scanner != null && scanner.getRunningScans() < scanner.getScannerType().getScanLimit()){
                updateWebAppService.removeFromQueue(webApp);
                for (WebAppScanClient webAppScanClient : webAppScanClients){
                    if (webAppScanClient.canProcessRequest(scanner)){
                        webAppScanClient.runScan(webApp,scanner);
                        updateScannerService.increaseScanNumber(scanner);
                        break;
                    }
                }
                log.debug("Starget scan for {} taken from queue", webApp.getUrl());
            } else if (scanner == null) {
                updateWebAppService.removeFromQueue(webApp);
                log.info("Cannot find proper scanner to scan {} removeing from queue", webApp.getUrl());
            }
        }
    }

    /**
     * Gets all projects with set AutoWebAppScan to true and then put every webapp linked with particular project
     * with priority=0 into queue
     */
    @Transactional
    public void scheduledRunWebAppScan(int priority) {
        log.info("Starting scheduled scan for webapps");
        List<Project> projects = findProjectService.findProjectsWithAutoWebAppScan();
        for (Project p : projects) {
            for (WebApp webApp : p.getWebapps()) {
                if (webApp.getPriority() == priority) {
                    this.putSingleWebAppToQueue(webApp.getId(), () -> Constants.STRATEGY_SCHEDULER);
                }
            }
        }
    }

    public ResponseEntity<Status>putSingleWebAppToQueue(Long webAppId, Principal principal) {
        try {
            Optional<WebApp> webApp = findWebAppService.findById(webAppId);
            if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal,webApp.get().getProject()) && getScannerService.getScannerForWebApp(webApp.get()) != null) {
                updateWebAppService.putWebAppToQueue(webApp.get(),UUID.randomUUID().toString());
                log.info("{} - Put in queue scan of webapps - scope single", LogUtil.prepare(principal.getName()));
                return new ResponseEntity<>(HttpStatus.CREATED);
            }
        } catch (Exception e){
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(new Status("No Scanner for given resource"), HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> putSelectedWebAppsToQueue(Long id, List<RunScanForWebApps> runScanForWebApps, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            for (RunScanForWebApps selectedApp : runScanForWebApps){
                try{
                    Optional<WebApp> webApp = findWebAppService.findById(selectedApp.getWebAppId());
                    if (webApp.isPresent() && Objects.equals(webApp.get().getProject().getId(), project.get().getId()) && getScannerService.getScannerForWebApp(webApp.get())!=null){
                        updateWebAppService.putWebAppToQueue(webApp.get(), UUID.randomUUID().toString());
                        log.info("{} - Put to queue scan of webapps for project {} - scope partial", LogUtil.prepare(principal.getName()), LogUtil.prepare(project.get().getName()));
                    }
                } catch (Exception e){
                    return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
                }
            }
            return new ResponseEntity<>(HttpStatus.CREATED);

        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }
}
