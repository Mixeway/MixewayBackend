package io.mixeway.rest.project.controller;

import io.mixeway.db.entity.Proxies;
import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.rest.project.model.ProjectVulnTrendChart;
import io.mixeway.rest.project.model.RiskCards;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import io.mixeway.rest.project.service.ProjectRestService;

import java.util.HashMap;
import java.util.List;

@RestController()
@RequestMapping("/v2/api/show/project")
public class ProjectRestController {
    private final ProjectRestService projectService;

    @Autowired
    ProjectRestController(ProjectRestService projectRestService){
        this.projectService =projectRestService;
    }

    //region Get User Role - views
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/risk")
    public ResponseEntity<RiskCards> showProjectRisk(@PathVariable("id")Long id) {
        return projectService.showProjectRisk(id);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/routingdomains")
    public ResponseEntity<List<RoutingDomain>> showRoutingDomains() {
        return projectService.showRoutingDomains();
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/proxies")
    public ResponseEntity<List<Proxies>> showProxies() {
        return projectService.showProxies();
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/vulntrendchart")
    public ResponseEntity<ProjectVulnTrendChart> showVulnTrendChart(@PathVariable("id")Long id) {
        return projectService.showVulnTrendChart(id);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/severitychart")
    public ResponseEntity<HashMap<String,Long>> showSeverityChart(@PathVariable("id")Long id) {
        return projectService.showSeverityChart(id);
    }

    //endregion


}
