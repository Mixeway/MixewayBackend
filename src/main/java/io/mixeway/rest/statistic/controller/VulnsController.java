package io.mixeway.rest.statistic.controller;

import io.mixeway.pojo.BarChartProjection2;
import io.mixeway.rest.statistic.service.VulnsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/v2/api/vulns")
public class VulnsController {
    VulnsService vulnsService;
    VulnsController(VulnsService vulnsService){
        this.vulnsService = vulnsService;
    }

    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/codevulns")
    public ResponseEntity<List<BarChartProjection2>> getCodeVulnsTop() {
        return vulnsService.getCodeVulnsTop();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/codeprojects")
    public ResponseEntity<List<BarChartProjection2>> getCodeProjectsTop() {
        return vulnsService.getCodeProjectsTop();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/infravulns")
    public ResponseEntity<List<BarChartProjection2>> getInfraVulnsTop() {
        return vulnsService.getInfraVulnsTop();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/infraintfs")
    public ResponseEntity<List<BarChartProjection2>> getInfraIntfsTop() {
        return vulnsService.getInfraIntfsTop();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/webvulns")
    public ResponseEntity<List<BarChartProjection2>> getWebVulnsTop() {
        return vulnsService.getWebVulnsTop();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/webapps")
    public ResponseEntity<List<BarChartProjection2>> getWebAppsTop() {
        return vulnsService.getWebAppsTop();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/opensource")
    public ResponseEntity<List<BarChartProjection2>> getOpenSourceVulns() {
        return vulnsService.getOpenSourceVulns();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/opensourceforcode")
    public ResponseEntity<List<BarChartProjection2>> getOpenSourceVulnsForCodeProject() {
        return vulnsService.getOpenSourceVulnsForCodeProject();
    }

}
