package io.mixeway.rest.dashboard.controller;


import io.mixeway.rest.dashboard.model.SearchRequest;
import io.mixeway.rest.dashboard.service.DashboardService;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import io.mixeway.rest.model.Projects;
import io.mixeway.rest.model.SourceDetectionChartData;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import io.mixeway.rest.dashboard.model.SearchResponse;
import io.mixeway.rest.dashboard.model.SessionOwner;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/v2/api/dashboard")
public class DashboardController {

    private final DashboardService dashboardService;

    DashboardController(DashboardService dashboardService){
        this.dashboardService = dashboardService;
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/userinfo")
    public ResponseEntity<SessionOwner> getSesstionOwner( HttpServletRequest request) {
        Authentication auth =         SecurityContextHolder.getContext().getAuthentication();

        return dashboardService.getSessionOwner(request.getUserPrincipal().getName());

    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/getvulntrenddata")
    public List<OverAllVulnTrendChartData> getVulnTrendData() throws IOException {
        return dashboardService.getVulnTrendData();
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/getsourcetrenddata")
    public SourceDetectionChartData getSourceTrendData() throws IOException {

        return dashboardService.getSourceTrendData();
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/projects")
    public List<Projects> getProjects(Principal principal) {
        return dashboardService.getProjects(principal);
    }

    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/projects/{projectName}/{projectDescription}/{ciid}/{enableVulnManage}")
    public ResponseEntity putProject(@PathVariable(value = "projectName") String projectName,
                                     @PathVariable(value="projectDescription") String projectDescription,
                                     @PathVariable(value="ciid") String ciid,
                                     @PathVariable(value="enableVulnManage") int enableVulnManage, Principal principal)  {
        return dashboardService.putProject(projectName, projectDescription, ciid, enableVulnManage, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PatchMapping(value = "/projects/{projectId}")
    public ResponseEntity editProject(@PathVariable(value = "projectId") Long projectId,
                                      @RequestBody Projects projectObject, Principal principal) {
        return dashboardService.patchProject(projectId,projectObject,principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/projects/{projectId}")
    public ResponseEntity deleteProject(@PathVariable(value = "projectId") Long projectId, Principal principal) {
        return dashboardService.deleteProject(projectId,principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PostMapping(value = "/search")
    public ResponseEntity<SearchResponse> search(@RequestBody SearchRequest searchRequest, Principal principal) {
        return dashboardService.search(searchRequest);
    }

}
