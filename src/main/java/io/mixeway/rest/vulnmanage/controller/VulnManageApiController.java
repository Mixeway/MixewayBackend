package io.mixeway.rest.vulnmanage.controller;

import io.mixeway.pojo.CIVulnManageResponse;
import io.mixeway.pojo.InfraScanMetadata;
import io.mixeway.rest.vulnmanage.model.Vulnerabilities;
import io.mixeway.rest.vulnmanage.service.GetVulnerabilitiesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.net.UnknownHostException;

@Controller
public class VulnManageApiController {

    private final GetVulnerabilitiesService getVulnerabilitiesService;

    @Autowired
    VulnManageApiController(GetVulnerabilitiesService getVulnerabilitiesService){
        this.getVulnerabilitiesService = getVulnerabilitiesService;
    }

    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value = "/api/koordynator/vulnerabilities",produces = "application/json")
    @Transactional(readOnly = true)
    public ResponseEntity<Vulnerabilities> getVulnerabilities() throws UnknownHostException {
       return getVulnerabilitiesService.getAllVulnerabilities();
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value = "/api/vulnerabilities/project/{projectId}",produces = "application/json")
    @Transactional(readOnly = true)
    public ResponseEntity<Vulnerabilities> getVulnerabilitiesForProject(@PathVariable(value = "projectId") Long id) throws UnknownHostException {
        return getVulnerabilitiesService.getVulnerabilitiesByProject(id);
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value = "/api/koordynator/vulnerabilities/{scannerType}",produces = "application/json")
    @Transactional(readOnly = true)
    public ResponseEntity<String> getVulnerabilitiesByType(@PathVariable(value = "scannerType") String type) throws UnknownHostException {

        return getVulnerabilitiesService.getVulnerabilitiesByType(type);
    }
    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value = "/api/vulns/{projectId}/{scannerType}",produces = "application/json")
    @Transactional(readOnly = true)
    public ResponseEntity<String> getVulnerabilitiesByTypeAndProject(@PathVariable(value = "scannerType") String type,@PathVariable(value = "projectId") Long id) throws UnknownHostException {
        return getVulnerabilitiesService.getVulnerabilitiesByProjectAndType(type, id);
    }
    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value = "/api/koordynator/vulnerabilities/networkScanner/metadata/{requestId}",produces = "application/json")
    public ResponseEntity<InfraScanMetadata> getMetadataForInfrastructureScan(@PathVariable(value = "requestId") String requestId ) {
        return getVulnerabilitiesService.getMetaDataForProject(requestId);
    }
    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value = "/api/koordynator/vulnerabilities/networkScanner/{requestId}",produces = "application/json")
    public ResponseEntity<Vulnerabilities> getNetworkVulnerabilitiesByRequestId(@PathVariable(value = "requestId") String requestId ) {
        return getVulnerabilitiesService.getNetworkVulnerabilitiesByRequestId(requestId);
    }

    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @GetMapping(value = "/api/vulns/{projectId}/{codeGroup}/{codeProject}",produces = "application/json")
    public ResponseEntity<CIVulnManageResponse> getVulnerabilities(@PathVariable(value = "codeGroup") String codeGroup,
                                                                   @PathVariable(value = "codeProject") String codeProject,
                                                                   @PathVariable(value = "projectId") Long id) {
        return getVulnerabilitiesService.getCiScoreForCodeProject(codeGroup,codeProject, id);
    }
}
