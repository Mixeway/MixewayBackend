package io.mixeway.api.project.controller;

import io.mixeway.api.project.model.AuditRequest;
import io.mixeway.api.project.model.RiskCards;
import io.mixeway.api.project.model.VulnAuditorSettings;
import io.mixeway.api.project.service.ProjectAuditService;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.WebApp;
import io.mixeway.domain.service.intf.FindInterfaceService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.VulnerabiltyAudit;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.security.Principal;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;

@RequestMapping("/v2/api/show/project/audit")
@RestController()
@RequiredArgsConstructor
public class ProjectAudit {

    private final ProjectAuditService projectAuditService;
    private final FindCodeProjectService findCodeProjectService;
    private final FindWebAppService findWebAppService;
    private final FindInterfaceService findInterfaceService;
    private final PermissionFactory permissionFactory;
    private final FindProjectService findProjectService;

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @PostMapping(value = "/code/{id}")
    public ResponseEntity<List<VulnerabiltyAudit>> getAuditForCodeVulnerability(@PathVariable("id")Long id, @Valid @RequestBody AuditRequest settings, Principal principal) {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
            return projectAuditService.getAuditForCodeVulnerability(codeProject.get(), settings);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @PostMapping(value = "/webapp/{id}")
    public ResponseEntity<List<VulnerabiltyAudit>> getAuditForWebAppVulnerability(@PathVariable("id")Long id, @Valid @RequestBody AuditRequest settings, Principal principal) {
        Optional<WebApp> webApp = findWebAppService.findById(id);
        if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
            return projectAuditService.getAuditForWebAppVulnerability(webApp.get(), settings);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @PostMapping(value = "/interface/{id}")
    public ResponseEntity<List<VulnerabiltyAudit>> getAuditForInterfaceVulnerability(@PathVariable("id")Long id, @Valid @RequestBody AuditRequest settings, Principal principal) {
        Optional<Interface> anInterface = findInterfaceService.findById(id);
        if (anInterface.isPresent() && permissionFactory.canUserAccessProject(principal, anInterface.get().getAsset().getProject())) {
            return projectAuditService.getAuditForAnInterfaceAppVulnerability(anInterface.get(), settings);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/project/{id}")
    public ResponseEntity<List<VulnerabiltyAudit>> getAuditForProjectVulnerability(@PathVariable("id")Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            return projectAuditService.getAuditForProjectVulnerability(project.get());
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/project/stats/{id}")
    public ResponseEntity<io.mixeway.utils.ProjectAudit> getAuditForProjectVulnerabilitySummarize(@PathVariable("id")Long id, Principal principal) throws ParseException {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            return projectAuditService.getAuditForProjectVulnerabilitySummarize(project.get());
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

}
