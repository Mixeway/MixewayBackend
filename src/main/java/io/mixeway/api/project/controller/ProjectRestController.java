package io.mixeway.api.project.controller;

import io.mixeway.api.project.model.*;
import io.mixeway.api.project.service.ProjectRestService;
import io.mixeway.db.entity.*;
import io.mixeway.utils.Status;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;

@RestController()
@RequestMapping("/v2/api/show/project")
public class  ProjectRestController {
    private final ProjectRestService projectService;

    ProjectRestController(ProjectRestService projectRestService){
        this.projectService =projectRestService;
    }

    //region Get User Role - views
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/risk")
    public ResponseEntity<RiskCards> showProjectRisk(@PathVariable("id")Long id, Principal principal) {
        return projectService.showProjectRisk(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/routingdomains")
    public ResponseEntity<List<RoutingDomain>> showRoutingDomains() {
        return projectService.showRoutingDomains();
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/allroutingdomains")
    public ResponseEntity<List<RoutingDomain>> showAllRoutingDomains() {
        return projectService.showAllRoutingDomains();
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/proxies")
    public ResponseEntity<List<Proxies>> showProxies() {
        return projectService.showProxies();
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/vulntrendchart")
    public ResponseEntity<ProjectVulnTrendChart> showVulnTrendChart(@PathVariable("id")Long id, Principal principal) {
        return projectService.showVulnTrendChart(id,7, principal);
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/vulntrendchart/days/{limit}")
    public ResponseEntity<ProjectVulnTrendChart> showVulnTrendChartWithLimit(@PathVariable("id")Long id, @PathVariable("limit") int limit, Principal principal) {
        return projectService.showVulnTrendChart(id,limit, principal);
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/severitychart")
    public ResponseEntity<HashMap<String,Long>> showSeverityChart(@PathVariable("id")Long id, Principal principal) {
        return projectService.showSeverityChart(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulnerabilities")
    public ResponseEntity<List<ProjectVulnerability>> showProjectVulnerabilities(@PathVariable("id")Long id, Principal principal) {
        return projectService.showVulnerabilitiesForProject(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulnerabilities/{vulnId}")
    public ResponseEntity<ProjectVulnerability> showVulnerability(@PathVariable("id")Long id, @PathVariable("vulnId")Long vulnId, Principal principal) {
        return projectService.showVulnerability(id,vulnId, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulnerabilities/{vulnId}/grade/{grade}")
    public ResponseEntity<Status> setGradeForVulnerability(@PathVariable("id")Long id, @PathVariable("vulnId")Long vulnId,
                                                                           @PathVariable("grade") int grade, Principal principal) {
        return projectService.setGradeForVulnerability(id,vulnId,grade, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PatchMapping(value = "/{id}/contactlist")
    public ResponseEntity<Status> updateContactList(@PathVariable("id")Long id, @RequestBody ContactList contactList, Principal principal) {
        return projectService.updateContactList(id,contactList, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/scannersavaliable")
    public ResponseEntity<List<ScannerType>> scannersAvaliable() {
        return projectService.scannersAvaliable();
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}")
    public ResponseEntity<Project> showProject(@PathVariable("id") Long id, Principal principal) {
        return projectService.showProject(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PostMapping(value = "/{id}/vulnauditor")
    public ResponseEntity<Status> updateVulnAuditorSettings(@PathVariable("id")Long id, @Valid @RequestBody VulnAuditorSettings settings, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return projectService.updateVulnAuditorSettings(id, settings, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/stats")
    public ResponseEntity<ProjectStats> showProjectStats(@PathVariable("id") Long id, Principal principal) {
        return projectService.showProjectStats(id, principal);
    }
    //endregion
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/ciid/{ciid}")
    public ResponseEntity<Project> getProjectByCiid(@PathVariable("ciid") String ciid, Principal principal) {
        return projectService.getProjectByCiid(ciid, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_PROJECT_OWNER')")
    @PostMapping(value = "/{id}/user/add")
    public ResponseEntity<Status> setProjectUser(@PathVariable("id") Long id, @RequestBody  ProjectUser user, Principal principal) {
        return projectService.setProjectUser(id,user,principal);
    }


    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/detailstats")
    public ResponseEntity<DetailStats> detailStats(@PathVariable("id") Long id, Principal principal) {
        return projectService.detailStats(id, principal);
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/detailedhistory")
    public ResponseEntity<List<VulnHistory>> detailedHistory(@PathVariable("id") Long id, Principal principal) {
        return projectService.detailedHistory(id, principal);
    }



}
