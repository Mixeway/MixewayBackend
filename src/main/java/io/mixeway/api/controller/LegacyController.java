package io.mixeway.api.controller;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.scanmanager.model.CodeAccessVerifier;
import io.mixeway.scanmanager.model.NetworkScanRequestModel;
import io.mixeway.scanmanager.model.WebAppScanRequestModel;
import io.mixeway.scanmanager.service.code.CodeScanService;
import io.mixeway.scanmanager.service.network.NetworkScanService;
import io.mixeway.scanmanager.service.webapp.WebAppScanService;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.codehaus.jettison.json.JSONException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Semaphore;

@RestController
@Log4j2
@RequiredArgsConstructor
public class LegacyController {
    private final CodeScanService codeScanService;
    private final NetworkScanService networkScanService;
    private final WebAppScanService webAppScanService;
    private static Semaphore semaphore = new Semaphore(1);
    private final PermissionFactory permissionFactory;
    private final FindProjectService findProjectService;

    @PreAuthorize("hasAuthority('ROLE_API')")
    @RequestMapping(value = "/api/koordynator/network",method = RequestMethod.POST)
    public ResponseEntity<Status> createAndRunNetworkscan(@RequestBody NetworkScanRequestModel req, Principal principal) throws Exception {
        return networkScanService.createAndRunNetworkScan(req, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @RequestMapping(value = "/api/koordynator/network/check/{ciid}",method = RequestMethod.GET)
    public ResponseEntity<Status> checkNetworkScanTest(@PathVariable("ciid") String ciid) {
        return networkScanService.checkScanStatusForCiid(ciid);
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/api/webapp/{projectId}")
    public ResponseEntity<Status> getWebApp(@PathVariable(value = "projectId") Long id, @RequestBody WebAppScanRequestModel req, Principal principal) throws InterruptedException {
        semaphore.acquire();
        try {
            Optional<Project> project = findProjectService.findProjectById(id);
            if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())) {
                return webAppScanService.processScanWebAppRequest(id, req.getWebApp(), Constants.STRATEGY_API, principal);
            } else {
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
        } finally {
            semaphore.release();
        }
    }

}
