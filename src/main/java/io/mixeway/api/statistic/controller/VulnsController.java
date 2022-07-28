package io.mixeway.api.statistic.controller;

import io.mixeway.api.statistic.service.VulnsService;
import io.mixeway.api.vulnmanage.model.GlobalStatistic;
import io.mixeway.db.entity.CisRequirement;
import io.mixeway.db.entity.Vulnerability;
import io.mixeway.db.projection.VulnBarChartProjection;
import io.mixeway.utils.Status;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/v2/api/vulns")
public class VulnsController {
    VulnsService vulnsService;
    VulnsController(VulnsService vulnsService){
        this.vulnsService = vulnsService;
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/codevulns")
    public ResponseEntity<List<VulnBarChartProjection>> getCodeVulnsTop(Principal principal) {
        return vulnsService.getCodeVulnsTop(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/codeprojects")
    public ResponseEntity<List<VulnBarChartProjection>> getCodeProjectsTop(Principal principal) {
        return vulnsService.getCodeProjectsTop(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/infravulns")
    public ResponseEntity<List<VulnBarChartProjection>> getInfraVulnsTop(Principal principal) {
        return vulnsService.getInfraVulnsTop(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/infraintfs")
    public ResponseEntity<List<VulnBarChartProjection>> getInfraIntfsTop(Principal principal) {
        return vulnsService.getInfraIntfsTop(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/webvulns")
    public ResponseEntity<List<VulnBarChartProjection>> getWebVulnsTop(Principal principal) {
        return vulnsService.getWebVulnsTop(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/webapps")
    public ResponseEntity<List<VulnBarChartProjection>> getWebAppsTop(Principal principal) {
        return vulnsService.getWebAppsTop(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/opensource")
    public ResponseEntity<List<VulnBarChartProjection>> getOpenSourceVulns(Principal principal) {
        return vulnsService.getOpenSourceVulns(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/opensourceforcode")
    public ResponseEntity<List<VulnBarChartProjection>> getOpenSourceVulnsForCodeProject(Principal principal) {
        return vulnsService.getOpenSourceVulnsForCodeProject(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/vulnerabilities")
    public ResponseEntity<List<Vulnerability>> getVulnerabilities(Principal principal) {
        return vulnsService.getVulnerabilities(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/cisrequirements")
    public ResponseEntity<List<CisRequirement>> getCisRequirements(Principal principal) {
        return vulnsService.getCisRequirements(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/vulnerabilities/{id}/{severity}")
    public ResponseEntity<Status> setVulnerabilitySeverity(@PathVariable(name = "id") Long id,
                                                           @PathVariable(name = "severity") String severity,
                                                           Principal principal) {
        return vulnsService.setVulnerabilitySeverity(id, severity, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/cisrequirements/{id}/{severity}")
    public ResponseEntity<Status> setCisRequirementSeverity(@PathVariable(name = "id") Long id,
                                                            @PathVariable(name = "severity") String severity,
                                                            Principal principal) {
        return vulnsService.setCisRequirementSeverity(id, severity, principal);
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/global/statistic",produces = "application/json")
    public ResponseEntity<List<GlobalStatistic>> getGlobalStatistics(Principal principal){
        return vulnsService.getGlobalStatistics(principal);

    }


}
