package io.mixeway.domain.service.scanmanager.webapp;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.WebAppRepository;
import io.mixeway.scanmanager.model.CustomCookie;
import io.mixeway.scanmanager.model.RequestHeaders;
import io.mixeway.scanmanager.model.WebAppScanModel;
import io.mixeway.utils.ProjectRiskAnalyzer;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class UpdateWebAppService {
    private final WebAppRepository webAppRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final FindWebAppService findWebAppService;

    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");


    public WebApp putWebAppToQueue(WebApp webApp, String requestId) {
        webApp.setInQueue(true);
        webApp.setRequestId(requestId);
        return webAppRepository.saveAndFlush(webApp);
    }
    public WebApp updateUrl(WebApp webApp, String url){
        webApp.setUrl(url);
        return webAppRepository.saveAndFlush(webApp);
    }

    public void endScan(WebApp app) {
        app.setRunning(false);
        webAppRepository.save(app);
    }

    /**
     * Update webapp by given model and put it into the scan queue.
     *
     * @param webAppScanModel model of app to create/update and scan
     * @param webApp to update
     * @return requestiD in form of UUID
     */
    public String updateAndPutWebAppToQueue(WebApp webApp, WebAppScanModel webAppScanModel, String requestId, boolean inQueue) throws ParseException {
        webApp.setUrl(webAppScanModel.getUrl());
        webApp.setInQueue(canPutWebAppToQueueDueToLastExecuted(webApp) && inQueue);
        webApp.setRequestId(requestId);
        webAppRepository.save(webApp);
        //webApp = setCodeProjectLink(webApp, webApp.getProject(), webAppScanModel);
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
     * Method which creates link between webapp and codeproject
     *
     * @param webApp to link
     * @param project to verify
     * @param sd model of application
     * @return webapplication with link
     */
//    public WebApp setCodeProjectLink(WebApp webApp, Project project, WebAppScanModel sd) {
//        if (sd.getCodeGroup() != null) {
//            Optional<CodeGroup> codeGroup = codeGroupRepository.findByProjectAndName(project, sd.getCodeGroup());
//            if (codeGroup.isPresent()) {
//                webApp.setCodeGroup(codeGroup.get());
//                log.info("Created link between CodeGroup {} and webapp {}", codeGroup.get().getName(), webApp.getUrl());
//                if (sd.getCodeProject() != null) {
//                    Optional<CodeProject> codeProject = codeProjectRepository.findByCodeGroupAndName(codeGroup.get(), sd.getCodeProject());
//                    if (codeProject.isPresent()) {
//                        webApp.setCodeProject(codeProject.get());
//                        log.info("Created link between CodeProject {} and webapp {}", codeProject.get().getName(), webApp.getUrl());
//                    }
//                }
//            }
//            webApp = webAppRepository.save(webApp);
//        }
//        return webApp;
//    }

    /**
     * Method which update WebAppHeaders and WebAppCoookie for existing webapp
     *
     * @param headers from request to update
     * @param cookies from request to update
     * @param webApp to update params
     */
    synchronized private void updateHeadersAndCookies(List<RequestHeaders> headers, List<CustomCookie> cookies, WebApp webApp) {
        if (headers != null) {
            getOrCreateWebAppService.removeHeadersForWebApp(webApp);
            for (RequestHeaders header : headers) {
                getOrCreateWebAppService.createWebAppHeader(header.getHeaderName(), header.getHeaderValue(), webApp);
            }
        }
        if (cookies != null) {
            getOrCreateWebAppService.removeCookiesForWebApp(webApp);
            webApp = webAppRepository.findById(webApp.getId()).orElse(null);
            for (CustomCookie customCookie : cookies) {
                getOrCreateWebAppService.createCookiesForWebApp(customCookie, webApp);
            }

        }
    }

    public void updateRisk(WebApp app) {
        app.setRisk(projectRiskAnalyzer.getWebAppRisk(app));
        webAppRepository.save(app);
    }
    public void removeFromQueue(WebApp app) {
        app.setInQueue(false);
        webAppRepository.save(app);
    }

    @Transactional
    public void setRisk() {
        for(WebApp webApp : webAppRepository.findAll()){
            webApp.setRisk(Math.min(projectRiskAnalyzer.getWebAppRisk(webApp), 100));
        }
    }

    @Transactional
    public void changeProjectForWebApps(Project source, Project destination){
        for (WebApp webApp : findWebAppService.findByProject(source)){
            webApp.setProject(destination);
            webAppRepository.saveAndFlush(webApp);
        }
    }
}
