package io.mixeway.integrations.webappscan.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.webappscan.model.CustomCookie;
import io.mixeway.integrations.webappscan.model.RequestHeaders;
import io.mixeway.integrations.webappscan.model.WebAppScanHelper;
import io.mixeway.integrations.webappscan.model.WebAppScanModel;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.pojo.Status;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.project.model.RunScanForWebApps;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.apache.catalina.loader.WebappClassLoader;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.UnexpectedRollbackException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;

import javax.persistence.NonUniqueResultException;
import java.security.Principal;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
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
    private final RoutingDomainRepository routingDomainRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final VaultHelper vaultHelper;
    private final VulnTemplate vulnTemplate;
    private final PermissionFactory permissionFactory;

    public WebAppScanService(ProjectRepository projectRepository, WebAppRepository waRepository, VulnTemplate vulnTemplate,
                             ScannerRepository scannerRepository, ScannerTypeRepository scannerTypeRepository,
                             CodeGroupRepository codeGroupRepository, CodeProjectRepository codeProjectRepository, WebAppCookieRepository webAppCookieRepository,
                             WebAppHeaderRepository webAppHeaderRepository, List<WebAppScanClient> webAppScanClients,
                             WebAppScanStrategyRepository webAppScanStrategyRepository, RoutingDomainRepository routingDomainRepository,
                             ProjectRiskAnalyzer projectRiskAnalyzer, VaultHelper vaultHelper, PermissionFactory permissionFactory) {
        this.projectRepository = projectRepository;
        this.projectRiskAnalyzer = projectRiskAnalyzer;
        this.vaultHelper = vaultHelper;
        this.waRepository = waRepository;
        this.scannerRepository = scannerRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.codeGroupRepository = codeGroupRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.webAppCookieRepository = webAppCookieRepository;
        this.webAppHeaderRepository = webAppHeaderRepository;
        this.webAppScanClients = webAppScanClients;
        this.webAppScanStrategyRepository = webAppScanStrategyRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.vulnTemplate = vulnTemplate;
        this.permissionFactory = permissionFactory;
    }

    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    /**
     * Check if url contains parameters and strip them from it
     *
     * @param url to compare
     * @return stripped url
     */
    private String getUrltoCompare(String url) {
        String urlToSend = url.split("\\?")[0];
        if (url.contains("?"))
            return urlToSend + "?";
        else
            return urlToSend;

    }

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
            String requestId;
            boolean success = true;
            StringBuilder status = new StringBuilder();
            Optional<Project> project = projectRepository.findById(id);
            if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
                requestId = UUID.randomUUID().toString();
                for (WebAppScanModel webAppScanModel : webAppScanModelList) {
                    Optional<WebApp> applicationToLoad = waRepository.findByProjectAndUrl(project.get(), webAppScanModel.getUrl());
                    if (applicationToLoad.isPresent()){
                        applicationToLoad.get().setInQueue(true);
                        applicationToLoad.get().setRequestId(requestId);
                        waRepository.save(applicationToLoad.get());
                        status.append(" ").append(applicationToLoad.get().getUrl()).append(" requested,");
                        //return new ResponseEntity<>(new Status("Scan is requested", requestId), HttpStatus.CREATED);
                    }
                    String urlToCompareSimiliar = getUrltoCompare(webAppScanModel.getUrl());
                    String urlToCompareWithRegexx = WebAppScanHelper.normalizeUrl(webAppScanModel.getUrl()) + "$";
                    try {
                        List<WebApp> webAppOptional = waRepository.getWebAppBySimiliarUrlOrRegexUrl(urlToCompareSimiliar, urlToCompareWithRegexx, project.get().getId());
                        if (webAppOptional.size() == 1){
                            updateAndPutWebAppToQueue(webAppOptional.stream().findFirst().get(), webAppScanModel, requestId);
                        } else if ( webAppOptional.size() == 0){
                            createAndPutWebAppToQueue(webAppScanModel, project.get(), origin,requestId);
                        } else {
                            log.warn("There is something really wrong With WebAppScan API: URL from request= {}, urlForSimiliarCheck= {}, urlForRegexChecl= {}", webAppScanModel.getUrl(),
                                    urlToCompareSimiliar, urlToCompareWithRegexx);
                            return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
                        }
                    } catch (NonUniqueResultException | IncorrectResultSizeDataAccessException | ParseException ex) {
                        return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
                    } catch (DataIntegrityViolationException | UnexpectedRollbackException e){
                        log.error("Cannot put {} into queue, error is dataintegrity violation, rollback..", urlToCompareWithRegexx);
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

    /**
     * Create webapp by given model and put it into the scan queue.
     *
     * @param webAppScanModel model of app to create/update and scan
     * @param project to link with webapp
     * @param origin origin of request. Required for Scan Strategy
     * @return requestiD in form of UUID
     */
    private String createAndPutWebAppToQueue(WebAppScanModel webAppScanModel, Project project, String origin, String requestId) {
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp = setCodeProjectLink(webApp, project, webAppScanModel);
        webApp.setRunning(false);
        webApp.setOrigin(origin);
        if (StringUtils.isNotBlank(webAppScanModel.getRoutingDomain()))
            webApp.setRoutingDomain(routingDomainRepository.findByName(webAppScanModel.getRoutingDomain()));
        webApp.setInQueue(true);
        webApp.setRequestId(requestId);
        webApp.setInserted(sdf.format(new Date()));
        webApp.setPublicscan(webAppScanModel.getIsPublic());
        webApp.setUrl(webAppScanModel.getUrl());
        webApp.setUsername(webAppScanModel.getUsername());
        String uuidToken = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(webAppScanModel.getPassword(), uuidToken)){
            webApp.setPassword(uuidToken);
        } else {
            webApp.setPassword(webAppScanModel.getPassword());
        }
        webApp = waRepository.save(webApp);
        waRepository.flush();
        this.createHeaderAndCookies(webAppScanModel.getHeaders(), webAppScanModel.getCookies(), webApp);
        log.info("Created WebApp '{}'", webApp.getUrl());
        waRepository.flush();
        return webApp.getRequestId();
    }

    /**
     * Update webapp by given model and put it into the scan queue.
     *
     * @param webAppScanModel model of app to create/update and scan
     * @param webApp to update
     * @return requestiD in form of UUID
     */
    private String updateAndPutWebAppToQueue(WebApp webApp, WebAppScanModel webAppScanModel, String requestId) throws ParseException {
        webApp.setUrl(webAppScanModel.getUrl());
        webApp.setInQueue(canPutWebAppToQueueDueToLastExecuted(webApp));
        webApp.setRequestId(requestId);
        waRepository.save(webApp);
        webApp = setCodeProjectLink(webApp, webApp.getProject(), webAppScanModel);
        this.updateHeadersAndCookies(webAppScanModel.getHeaders(), webAppScanModel.getCookies(), webApp);
        log.debug("Modified WebApp '{}' and set {} headers", webApp.getUrl(), webApp.getHeaders() == null? 0 : webApp.getHeaders().size());
        return webApp.getRequestId();
    }

    /**
     * Method which verify if webapp should be put into the queue. If there was 8 hours between last scan exeution and current request scan is not put into queue.
     *
     * @param webApp to check
     * @return information if there was a scan executed within last 8 hours
     */
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

    /**
     * Method which update WebAppHeaders and WebAppCoookie for existing webapp
     *
     * @param headers from request to update
     * @param cookies from request to update
     * @param webApp to update params
     */
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

    /**
     * Method which creates headers and cookies for new webapp
     *
     * @param headers from request
     * @param cookies from request
     * @param webApp to link with headers and cookies
     */
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

    /**
     * Method which use regex function of SQL to check for duplicates of given URL
     *
     * @param url to check for duplicates
     * @param id of system to check
     * @return list of webapplication which match regex
     */
    private List<WebApp> checkRegexes(String url, Long id) {
        return waRepository.getWebAppByRegexAsList(url + "$", id);
    }

    /**
     * Removes cookies from webapp
     *
     * @param webApp to get cookies
     */
    private void removeCookiesForWebApp(WebApp webApp) {
        webAppCookieRepository.deleteCookiesForWebApp(webApp.getId());
    }

    /**
     * Remove headers from webapp
     *
     * @param webApp to get headers
     */
    private void removeHeadersForWebApp(WebApp webApp) {
        webAppHeaderRepository.deleteHeaderForWebApp(webApp.getId());
    }

    /**
     * Method which creates link between webapp and codeproject
     *
     * @param webApp to link
     * @param project to verify
     * @param sd model of application
     * @return webapplication with link
     */
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
    @Transactional
    public void scheduledCheckAndDownloadResults() throws Exception {
        List<WebApp> apps = waRepository.findByRunning(true);
        for (WebApp app : apps) {
            Scanner scanner = getScannerForWebApp(app);
            try {
                if (scanner != null ) {
                    for (WebAppScanClient webAppScanClient : webAppScanClients) {
                        if (webAppScanClient.canProcessRequest(scanner) && webAppScanClient.isScanDone(scanner, app)) {
                            List<ProjectVulnerability> tmpVulns = vulnTemplate.projectVulnerabilityRepository.findByWebApp(app);
                            if (tmpVulns.size() > 0) {
                                vulnTemplate.projectVulnerabilityRepository.updateVulnState(tmpVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList()),
                                        vulnTemplate.STATUS_REMOVED.getId());
                                tmpVulns.forEach(v -> v.setStatus(vulnTemplate.STATUS_REMOVED));
                            }
                            //vulnTemplate.projectVulnerabilityRepository.deleteByWebApp(app);
                            app = waRepository.getOne(app.getId());
                            webAppScanClient.loadVulnerabilities(scanner,app, null, tmpVulns);
                            scanner.setRunningScans(scanner.getRunningScans() - 1);
                            scannerRepository.save(scanner);
                            app.setRisk(projectRiskAnalyzer.getWebAppRisk(app));
                            vulnTemplate.projectVulnerabilityRepository.deleteByStatus(vulnTemplate.STATUS_REMOVED);
                            break;
                        }
                    }
                }
            } catch (HttpClientErrorException e) {
                if (e.getRawStatusCode() == 404) {
                    deactivateWebApp(app);
                    scanner.setRunningScans(scanner.getRunningScans()-1);
                    log.warn("WebApp deleted manualy from scanner - {} {}", e.getRawStatusCode(), app.getUrl());
                } else {
                    scanner.setRunningScans(scanner.getRunningScans() - 1);
                    scannerRepository.save(scanner);
                    log.warn("HttpClientException with code {} for webapp {}", e.getRawStatusCode(), app.getUrl());
                }
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
     */
    @Transactional
    public void scheduledRunWebAppScanFromQueue() throws Exception {
        List<WebApp> webApps = waRepository.findByInQueue(true);
        for (WebApp webApp : webApps){
            Scanner scanner = getScannerForWebApp(webApp);
            if (scanner != null && scanner.getRunningScans() < scanner.getScannerType().getScanLimit()){
                webApp.setInQueue(false);
                for (WebAppScanClient webAppScanClient : webAppScanClients){
                    if (webAppScanClient.canProcessRequest(scanner)){
                        webAppScanClient.runScan(webApp,scanner);
                        scanner.setRunningScans(scanner.getRunningScans()+1);
                        break;
                    }
                }
                log.debug("Starget scan for {} taken from queue", webApp.getUrl());
            } else if (scanner == null) {
                webApp.setInQueue(false);
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
        List<Project> projects = projectRepository.findByAutoWebAppScan(true);
        for (Project p : projects) {
            for (WebApp webApp : p.getWebapps()) {
                if (webApp.getPriority() == priority) {
                    this.putSingleWebAppToQueue(webApp.getId(), () -> Constants.STRATEGY_SCHEDULER);
                }
            }
        }
    }

    public ResponseEntity<Status> putSingleWebAppToQueue(Long webAppId, Principal principal) {
        try {
            Optional<WebApp> webApp = waRepository.findById(webAppId);
            if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal,webApp.get().getProject()) && getScannerForWebApp(webApp.get()) != null) {
                webApp.ifPresent(app -> app.setInQueue(true));
                waRepository.save(webApp.get());
                log.info("{} - Put in queue scan of webapps - scope single", LogUtil.prepare(principal.getName()));
                return new ResponseEntity<>(HttpStatus.CREATED);
            }
        } catch (Exception e){
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(new Status("No Scanner for given resource"), HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> putSelectedWebAppsToQueue(Long id, List<RunScanForWebApps> runScanForWebApps, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            for (RunScanForWebApps selectedApp : runScanForWebApps){
                try{
                    Optional<WebApp> webApp = waRepository.findById(selectedApp.getWebAppId());
                    if (webApp.isPresent() && webApp.get().getProject() == project.get() && getScannerForWebApp(webApp.get())!=null){
                        webApp.get().setInQueue(true);
                        waRepository.save(webApp.get());
                        log.info("{} - Put to queue scan of webapps for project {} - scope partial", LogUtil.prepare(principal.getName()), LogUtil.prepare(project.get().getName()));
                        return new ResponseEntity<>(HttpStatus.CREATED);
                    }
                } catch (Exception e){
                    return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
                }
            }

        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
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
                List<ScannerType> scannerTypes = scannerTypeRepository.findByCategory(Constants.SCANER_CATEGORY_WEBAPP);
                scanner = scannerRepository.findByScannerTypeInAndRoutingDomain(scannerTypeRepository.findByCategory(Constants.SCANER_CATEGORY_WEBAPP), webApp.getRoutingDomain());
            }
        }
        return scanner;
    }
}
