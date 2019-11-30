package io.mixeway.plugins.webappscan.controller;

import io.mixeway.domain.service.project.GetOrCreateProjectService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import io.mixeway.plugins.webappscan.model.WebAppScanRequestModel;
import io.mixeway.plugins.webappscan.service.WebAppScanService;
import io.mixeway.pojo.Status;

import javax.transaction.Transactional;
import java.util.concurrent.Semaphore;

@RestController
public class WebAppApiController {
    private final WebAppScanService webAppScanService;
    private final GetOrCreateProjectService projectService;
    private static final Logger LOGGER = LoggerFactory.getLogger(WebAppApiController.class);
    private static Semaphore semaphore = new Semaphore(1);
    @Autowired
    WebAppApiController(GetOrCreateProjectService getOrCreateProjectService, WebAppScanService webAppScanService){
        this.projectService = getOrCreateProjectService;
        this.webAppScanService = webAppScanService;
    }


    @Transactional
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/api/webapp/{projectId}")
    public ResponseEntity<Status> getWebApp(@PathVariable(value = "projectId") Long id, @RequestBody WebAppScanRequestModel req) throws InterruptedException {
        LOGGER.debug("Starting to process webapp scan taken from self care api");
        semaphore.acquire();
        try {
            return webAppScanService.processScanWebAppRequest(id, req.getWebApp());
        } finally {
            semaphore.release();
        }
    }
    @Transactional
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/api/koordynator/webapp")
    public ResponseEntity<Status> createWebAppScanFromKoordynator(@RequestBody WebAppScanRequestModel req) {
        LOGGER.debug("Starting to process webapp scan taken fron koordynator");
        String ciid = req.getCiid().orElse("");
        String projectName = req.getProjectName().orElse("");
        return webAppScanService.processScanWebAppRequest(projectService.getProjectId(ciid, projectName), req.getWebApp());
    }
}
