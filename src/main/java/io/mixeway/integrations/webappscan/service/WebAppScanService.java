package io.mixeway.integrations.webappscan.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.integrations.webappscan.model.CustomCookie;
import io.mixeway.integrations.webappscan.model.RequestHeaders;
import io.mixeway.integrations.webappscan.model.WebAppScanHelper;
import io.mixeway.integrations.webappscan.model.WebAppScanModel;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.Status;
import io.mixeway.rest.project.model.RunScanForWebApps;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;

import javax.persistence.NonUniqueResultException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
public class WebAppScanService {
    private static final Logger log = LoggerFactory.getLogger(WebAppScanService.class);
    private final ProjectRepository projectRepository;
    private final WebAppRepository waRepository;
    private final WebAppHeaderRepository webAppHeaderRepository;
    private final WebAppScanStrategyRepository webAppScanStrategyRepository;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final CodeGroupRepository codeGroupRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final WebAppCookieRepository webAppCookieRepository;
    private final List<WebAppScanClient> webAppScanClients;
    private final WebAppVulnRepository webAppVulnRepository;
    private final RoutingDomainRepository routingDomainRepository;

    public WebAppScanService(ProjectRepository projectRepository, WebAppRepository waRepository, WebAppVulnRepository webAppVulnRepository,
                             ScannerRepository scannerRepository, ScannerTypeRepository scannerTypeRepository,
                             CodeGroupRepository codeGroupRepository, CodeProjectRepository codeProjectRepository, WebAppCookieRepository webAppCookieRepository,
                             WebAppHeaderRepository webAppHeaderRepository, List<WebAppScanClient> webAppScanClients,
                             WebAppScanStrategyRepository webAppScanStrategyRepository, RoutingDomainRepository routingDomainRepository) {
        this.projectRepository = projectRepository;
        this.waRepository = waRepository;
        this.scannerRepository = scannerRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.codeGroupRepository = codeGroupRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.webAppCookieRepository = webAppCookieRepository;
        this.webAppHeaderRepository = webAppHeaderRepository;
        this.webAppScanClients = webAppScanClients;
        this.webAppVulnRepository = webAppVulnRepository;
        this.webAppScanStrategyRepository = webAppScanStrategyRepository;
        this.routingDomainRepository = routingDomainRepository;
    }

    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private String getUrltoCompare(String url) {
        String urlToSend = url.split("\\?")[0];
        if (url.contains("?"))
            return urlToSend + "?";
        else
            return urlToSend;

    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ResponseEntity<Status> processScanWebAppRequest(Long id, List<WebAppScanModel> webAppScanModelList, String origin) {
        synchronized (this) {
            String requestId = null;
            Optional<Project> project = projectRepository.findById(id);
            Optional<Scanner> scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_ACUNETIX)).stream().findFirst();
            if (project.isPresent() && scanner.isPresent()) {
                for (WebAppScanModel webAppScanModel : webAppScanModelList) {
                    try {
                        String urlToLookFor = WebAppScanHelper.normalizeUrl(webAppScanModel.getUrl());
                        Optional<WebApp> webAppOptional = waRepository.getWebAppWithSimiliarUrlForProject(getUrltoCompare(webAppScanModel.getUrl()), project.get().getId());
                        if (webAppOptional.isPresent()) {
                            requestId = updateAndPutWebAppToQueue(webAppOptional.get(), webAppScanModel);
                        } else {
                            List<WebApp> webAppsByRegex = checkRegexes(urlToLookFor, project.get().getId());
                            if (webAppsByRegex.size() > 0) {
                                requestId = updateAndPutWebAppToQueue(getProperWebAppForUpdate(webAppsByRegex), webAppScanModel);
                            } else {
                                requestId = createAndPutWebAppToQueue(webAppScanModel, project.get(), origin);
                            }
                        }
                    } catch (NonUniqueResultException | IncorrectResultSizeDataAccessException | ParseException ex) {
                        waRepository.flush();
                        return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
                    }
                }
                waRepository.flush();
                return new ResponseEntity<>(new Status("Scan is requested", requestId), HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
        }
    }

    private WebApp getProperWebAppForUpdate(List<WebApp> webAppsByRegex) {
        if (webAppsByRegex.size() > 1) {
            WebApp webApp = webAppsByRegex.get(0);
            webAppsByRegex.remove(webApp);
            for (WebApp wa : webAppsByRegex) {
                waRepository.delete(wa);
            }
            waRepository.flush();
            return webApp;
        } else {
            return webAppsByRegex.get(0);
        }
    }

    private String createAndPutWebAppToQueue(WebAppScanModel webAppScanModel, Project project, String origin) {
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp = setCodeProjectLink(webApp, project, webAppScanModel);
        webApp.setRunning(false);
        webApp.setOrigin(origin);
        if (StringUtils.isNotBlank(webAppScanModel.getRoutingDomain()))
            webApp.setRoutingDomain(routingDomainRepository.findByName(webAppScanModel.getRoutingDomain()));
        webApp.setInQueue(true);
        webApp.setRequestId(UUID.randomUUID().toString());
        webApp.setInserted(sdf.format(new Date()));
        webApp.setPublicscan(webAppScanModel.getIsPublic());
        webApp.setUrl(webAppScanModel.getUrl());
        webApp = waRepository.save(webApp);
        waRepository.flush();
        this.createHeaderAndCookies(webAppScanModel.getHeaders(), webAppScanModel.getCookies(), webApp);
        log.info("Created WebApp '{}'", webApp.getUrl());
        waRepository.flush();
        return webApp.getRequestId();
    }

    private String updateAndPutWebAppToQueue(WebApp webApp, WebAppScanModel webAppScanModel) throws ParseException {
        webApp.setUrl(webAppScanModel.getUrl());
        webApp.setInQueue(canPutWebAppToQueueDueToLastExecuted(webApp));
        webApp.setRequestId(UUID.randomUUID().toString());
        waRepository.save(webApp);
        webApp = setCodeProjectLink(webApp, webApp.getProject(), webAppScanModel);
        this.updateHeadersAndCookies(webAppScanModel.getHeaders(), webAppScanModel.getCookies(), webApp);
        log.debug("Modified WebApp '{}' and set {} headers", webApp.getUrl(), webApp.getHeaders().size());
        return webApp.getRequestId();
    }

    private boolean canPutWebAppToQueueDueToLastExecuted(WebApp webApp) throws ParseException {
        if (webApp.getRunning()) {
            return false;
        } else if (webApp.getLastExecuted() == null) {
            return true;
        } else {
            Date dtExecuted = sdf.parse(webApp.getLastExecuted());
            long diff = new Date().getTime() - dtExecuted.getTime();
            return TimeUnit.MILLISECONDS.toHours(diff) > 8;
        }
    }

    synchronized private void updateHeadersAndCookies(List<RequestHeaders> headers, List<CustomCookie> cookies, WebApp webApp) {
        if (headers != null) {
            removeHeadersForWebApp(webApp);
            for (RequestHeaders header : headers) {
                createWebAppHeader(header.getHeaderName(), header.getHeaderValue(), webApp);
            }
        }
        if (cookies != null) {
            removeCookiesForWebApp(webApp);
            webApp = waRepository.findById(webApp.getId()).orElse(null);
            for (CustomCookie customCookie : cookies) {
                createCookiesForWebApp(customCookie, webApp);
            }

        }
    }

    synchronized private void createHeaderAndCookies(List<RequestHeaders> headers, List<CustomCookie> cookies, WebApp webApp) {
        if (headers != null) {
            for (RequestHeaders header : headers) {
                createWebAppHeader(header.getHeaderName(), header.getHeaderValue(), webApp);
            }
        }
        if (cookies != null) {
            for (CustomCookie cookie : cookies) {
                createCookiesForWebApp(cookie, webApp);
            }
        }
    }

    private List<WebApp> checkRegexes(String url, Long id) {
        return waRepository.getWebAppByRegexAsList(url + "$", id);
    }

    private void removeCookiesForWebApp(WebApp webApp) {
        webAppCookieRepository.deleteCookiesForWebApp(webApp.getId());
    }

    private void removeHeadersForWebApp(WebApp webApp) {
        webAppHeaderRepository.deleteHeaderForWebApp(webApp.getId());
    }

    private WebApp setCodeProjectLink(WebApp webApp, Project project, WebAppScanModel sd) {
        if (sd.getCodeGroup() != null) {
            Optional<CodeGroup> codeGroup = codeGroupRepository.findByProjectAndName(project, sd.getCodeGroup());
            if (codeGroup.isPresent()) {
                webApp.setCodeGroup(codeGroup.get());
                log.info("Created link between CodeGroup {} and webapp {}", codeGroup.get().getName(), webApp.getUrl());
                if (sd.getCodeProject() != null) {
                    Optional<CodeProject> codeProject = codeProjectRepository.findByCodeGroupAndName(codeGroup.get(), sd.getCodeProject());
                    if (codeProject.isPresent()) {
                        webApp.setCodeProject(codeProject.get());
                        log.info("Created link between CodeProject {} and webapp {}", codeProject.get().getName(), webApp.getUrl());
                    }
                }
            }
            webApp = waRepository.save(webApp);
        }
        return webApp;
    }

    private void createWebAppHeader(String headerName, String headerValue, WebApp webApp) {
        WebAppHeader waHeaderNew = new WebAppHeader();
        waHeaderNew.setHeaderName(headerName);
        waHeaderNew.setHeaderValue(headerValue);
        waHeaderNew.setWebApp(webApp);
        webAppHeaderRepository.save(waHeaderNew);
        if (webApp.getHeaders() == null) {
            List<WebAppHeader> webAppHeaders = new ArrayList<>();
            webAppHeaders.add(waHeaderNew);
            webApp.setHeaders(new HashSet<>(webAppHeaders));

        } else {
            webApp.getHeaders().add(waHeaderNew);
        }
        waRepository.save(webApp);
    }

    private void createCookiesForWebApp(CustomCookie cookie, WebApp webApp) {
        WebAppCookies wac = new WebAppCookies();
        wac.setWebApp(webApp);
        wac.setCookie(cookie.getCookie());
        wac.setUrl(webApp.getUrl().split("/")[0] + "//" + webApp.getUrl().split("/")[2]);
        webAppCookieRepository.save(wac);
        if (webApp.getWebAppCookies() == null) {
            List<WebAppCookies> webAppCookies = new ArrayList<>();
            webAppCookies.add(wac);
            webApp.setWebAppCookies(new HashSet<>(webAppCookies));

        } else {
            webApp.getWebAppCookies().add(wac);
        }
        waRepository.save(webApp);
    }

    /**
     * Finding WebApp with Runninng= true and check if scan is ended
     * then it decrease number of running scan for particular scanner
     *
     * @throws Exception
     */
    public void scheduledCheckAndDownloadResults() throws Exception {
        List<WebApp> apps = waRepository.findByRunning(true);
        for (WebApp app : apps) {
            try {
                Scanner scanner = getScannerForWebApp(app);
                if (scanner != null ) {
                    for (WebAppScanClient webAppScanClient : webAppScanClients) {
                        if (webAppScanClient.canProcessRequest(scanner) && webAppScanClient.isScanDone(scanner, app)) {
                            List<WebAppVuln> tmpVulns = new ArrayList<>();
                            if (app.getVulns().size() > 0) {
                                tmpVulns = webAppVulnRepository.findByWebApp(app);
                                webAppVulnRepository.deleteByWebApp(app);
                                app = waRepository.getOne(app.getId());
                            }
                            webAppScanClient.loadVulnerabilities(scanner,app, null, tmpVulns);
                            scanner.setRunningScans(scanner.getRunningScans()-1);
                            break;
                        }
                    }
                }
            } catch (HttpClientErrorException e) {
                if (e.getRawStatusCode() == 404) {
                    deactivateWebApp(app);
                    log.warn("WebApp deleted manualy from acunetix - {} {}", e.getRawStatusCode(), app.getUrl());
                } else
                    log.warn("HttpClientException with code {} for webapp {}", e.getRawStatusCode(), app.getUrl());
            }
        }
    }

    private void deactivateWebApp(WebApp app) {
        app.setRunning(false);
        waRepository.save(app);
    }

    /**
     * Method which takes WebApps with inQueue = true
     * Check if Scanner for particular App is limit free and then run the scan for this app.
     * If Limit is exceeded webapp is left inqueue
     *
     * @throws Exception
     */
    @Transactional
    public void scheduledRunWebAppScanFromQueue() throws Exception {
        List<WebApp> webApps = waRepository.findByInQueue(true);
        for (WebApp webApp : webApps){
            Scanner scanner = getScannerForWebApp(webApp);
            if (scanner != null && scanner.getRunningScans() < Constants.WEBAPP_SCAN_LIMIT){
                webApp.setInQueue(false);
                for (WebAppScanClient webAppScanClient : webAppScanClients){
                    if (webAppScanClient.canProcessRequest(scanner)){
                        webAppScanClient.runScan(webApp,scanner);
                        scanner.setRunningScans(scanner.getRunningScans()+1);
                        break;
                    }
                }
                log.debug("Starget scan for {} taken from queue", webApp.getUrl());

            }
        }
    }

    @Transactional
    public void scheduledRunWebAppScan() {
        List<Project> projects = projectRepository.findByAutoWebAppScan(true);
        for (Project p : projects) {
            for (WebApp webApp : p.getWebapps()) {
                webApp.setInQueue(true);
            }
        }
    }

    public ResponseEntity<Status> putSingleWebAppToQueue(Long webAppId, String username) {
        try {
            Optional<WebApp> webApp = waRepository.findById(webAppId);
            webApp.ifPresent(app -> app.setInQueue(true));
            waRepository.save(webApp.get());
        } catch (Exception e){
            return new ResponseEntity<>(null, HttpStatus.EXPECTATION_FAILED);
        }
        log.info("{} - Put in queue scan of webapps - scope single", LogUtil.prepare(username));
        return new ResponseEntity<>(null,HttpStatus.CREATED);
    }

    public ResponseEntity<Status> putSelectedWebAppsToQueue(Long id, List<RunScanForWebApps> runScanForWebApps, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            for (RunScanForWebApps selectedApp : runScanForWebApps){
                try{
                    Optional<WebApp> webApp = waRepository.findById(selectedApp.getWebAppId());
                    if (webApp.isPresent() && webApp.get().getProject() == project.get()){
                        webApp.get().setInQueue(true);
                        waRepository.save(webApp.get());
                    }
                } catch (Exception e){
                    return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
                }
            }
            log.info("{} - Put to queue scan of webapps for project {} - scope partial", LogUtil.prepare(username), LogUtil.prepare(project.get().getName()));
            return new ResponseEntity<>(null,HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    private Scanner getScannerForWebApp(WebApp webApp){
        WebAppScanStrategy webAppScanStrategy = webAppScanStrategyRepository.findAll().stream().findFirst().orElse(null);
        Scanner scanner = null;
        if (webAppScanStrategy != null ){
            if (webAppScanStrategy.getApiStrategy() != null && webApp.getOrigin().equals(Constants.STRATEGY_API)){
                scanner = scannerRepository.findByScannerType(webAppScanStrategy.getApiStrategy()).stream().findFirst().orElse(null);
            }
            else if (webAppScanStrategy.getGuiStrategy() != null && webApp.getOrigin().equals(Constants.STRATEGY_GUI)){
                scanner = scannerRepository.findByScannerType(webAppScanStrategy.getGuiStrategy()).stream().findFirst().orElse(null);
            } else if (webAppScanStrategy.getScheduledStrategy() != null && webApp.getOrigin().equals(Constants.STRATEGY_SCHEDULER)){
                scanner = scannerRepository.findByScannerType(webAppScanStrategy.getScheduledStrategy()).stream().findFirst().orElse(null);
            } else {
                scanner = scannerRepository.findByScannerTypeInAndRoutingDomain(scannerTypeRepository.findByCategory(Constants.SCANER_CATEGORY_WEBAPP), webApp.getRoutingDomain());
            }
        }
        return scanner;
    }
}
