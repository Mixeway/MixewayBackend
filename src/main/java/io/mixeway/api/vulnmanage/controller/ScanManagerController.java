package io.mixeway.api.vulnmanage.controller;

import io.mixeway.api.vulnmanage.model.*;
import io.mixeway.api.vulnmanage.service.GetVulnerabilitiesService;
import io.mixeway.api.vulnmanage.service.ScanManagerService;
import io.mixeway.utils.Status;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.validation.Valid;
import java.net.UnknownHostException;
import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/v2/api/scanmanage")
public class ScanManagerController {
    private final ScanManagerService scanManagerService;
    private final GetVulnerabilitiesService getVulnerabilitiesService;

    ScanManagerController(final ScanManagerService scanManagerService, final GetVulnerabilitiesService getVulnerabilitiesService){
        this.scanManagerService = scanManagerService;
        this.getVulnerabilitiesService = getVulnerabilitiesService;
    }

    @PreAuthorize("hasAuthority('ROLE_API')")
    @PutMapping(value = "/create",produces = "application/json")
    public ResponseEntity<Status> createScanManageRequest(@Valid @RequestBody CreateScanManageRequest createScanManageRequest, Principal principal,
                                                          Errors errors) throws Exception {
        if (errors.hasErrors() || !createScanManageRequest.isValid()){
            return new ResponseEntity<>(new Status("Allowed testTypes are: `network`,`webApp`,`code`"), HttpStatus.BAD_REQUEST);
        } else {
            return scanManagerService.createScanManageRequest(createScanManageRequest, principal);
        }
    }

    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value= "/check/{requestId}")
    @Validated
    public ResponseEntity<Status> checkStatusOfRequestedScan(@Valid RequestId requestId, Errors errors, Principal principal){
        if (errors.hasErrors()){
            return new ResponseEntity<>(new Status("UUID format required"), HttpStatus.BAD_REQUEST);
        } else {
            return scanManagerService.checkStatusOfRequestedScan(requestId.toString());
        }
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value= "/vulnerabilities/{requestId}/metadata")
    public ResponseEntity<InfraScanMetadata> getMetadataForScanByRequestId(@Valid RequestId requestId, Errors errors, Principal principal ) {
        if (errors.hasErrors()){
            return new ResponseEntity<>( HttpStatus.BAD_REQUEST);
        } else {
            return getVulnerabilitiesService.getMetaDataForProject(requestId.toString());
        }

    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value= "/vulnerabilities/{requestId}")
    public ResponseEntity<Vulnerabilities> getVulnerabilitiesForScanByReqeustId(@Valid RequestId requestId, Errors errors, Principal principal) throws UnknownHostException {
        if (errors.hasErrors()){
            return new ResponseEntity<>( HttpStatus.BAD_REQUEST);
        } else {
            return scanManagerService.getVulnerabilitiesForScanByReqeustId(requestId.toString(), principal);
        }
    }

    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value="/running/scans")
    public ResponseEntity<List<SecurityScans>> getRunningSecurityScans(){
        return scanManagerService.getRunningSecurityScans();
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value="/inqueue/scans")
    public ResponseEntity<List<SecurityScans>> getInQueueSecurityScans(){
        return scanManagerService.getInQueueSecurityScans();
    }

}
