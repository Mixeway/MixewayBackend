package io.mixeway.rest.vulnmanage.controller;

import io.mixeway.rest.vulnmanage.model.CreateScanManageRequest;
import io.mixeway.rest.vulnmanage.service.ScanManagerService;
import org.codehaus.jettison.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import io.mixeway.pojo.InfraScanMetadata;
import io.mixeway.pojo.Status;
import io.mixeway.rest.vulnmanage.model.RequestId;
import io.mixeway.rest.vulnmanage.model.Vulnerabilities;
import io.mixeway.rest.vulnmanage.service.GetVulnerabilitiesService;
import springfox.documentation.annotations.ApiIgnore;

import javax.validation.Valid;
import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;

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
    public ResponseEntity<Status> checkStatusOfRequestedScan(@Valid RequestId requestId, @ApiIgnore Errors errors){
        if (errors.hasErrors()){
            return new ResponseEntity<>(new Status("UUID format required"), HttpStatus.BAD_REQUEST);
        } else {
            return scanManagerService.checkStatusOfRequestedScan(requestId.toString());
        }
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value= "/vulnerabilities/{requestId}/metadata")
    public ResponseEntity<InfraScanMetadata> getMetadataForScanByRequestId(@Valid RequestId requestId, @ApiIgnore Errors errors ) {
        if (errors.hasErrors()){
            return new ResponseEntity<>( HttpStatus.BAD_REQUEST);
        } else {
            return getVulnerabilitiesService.getMetaDataForProject(requestId.toString());
        }

    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value= "/vulnerabilities/{requestId}")
    public ResponseEntity<Vulnerabilities> getVulnerabilitiesForScanByReqeustId(@Valid RequestId requestId, @ApiIgnore Errors errors) throws UnknownHostException {
        if (errors.hasErrors()){
            return new ResponseEntity<>( HttpStatus.BAD_REQUEST);
        } else {
            return scanManagerService.getVulnerabilitiesForScanByReqeustId(requestId.toString());
        }

    }

}
