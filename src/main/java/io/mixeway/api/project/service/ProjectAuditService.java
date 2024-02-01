package io.mixeway.api.project.service;

import io.mixeway.api.project.model.AuditRequest;
import io.mixeway.api.project.model.VulnAuditorSettings;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.WebApp;
import io.mixeway.domain.service.projectvulnerability.FindProjectVulnerabilityAuditService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.utils.ProjectAudit;
import io.mixeway.utils.VulnerabiltyAudit;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Log4j2
public class ProjectAuditService {
    private final FindProjectVulnerabilityAuditService findProjectVulnerabilityAuditService;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;

    public ResponseEntity<List<VulnerabiltyAudit>> getAuditForCodeVulnerability(CodeProject codeProject, AuditRequest settings) {

        List<VulnerabiltyAudit> vulnerabiltyAudits = findProjectVulnerabilityAuditService.getCodeVulnerabilityHistory(
                codeProject,
                settings.getLocation(),
                createOrGetVulnerabilityService.createOrGetVulnerability(settings.getVulnerability()
                ));
        return new ResponseEntity<>(vulnerabiltyAudits, HttpStatus.OK);
    }

    public ResponseEntity<List<VulnerabiltyAudit>> getAuditForWebAppVulnerability(WebApp webApp, AuditRequest settings) {
        return new ResponseEntity<>(
                findProjectVulnerabilityAuditService.getWebAppHistory(
                        webApp,
                        settings.getLocation(),
                        createOrGetVulnerabilityService.createOrGetVulnerability(settings.getVulnerability()
                        )
                ), HttpStatus.OK);
    }


    public ResponseEntity<List<VulnerabiltyAudit>> getAuditForAnInterfaceAppVulnerability(Interface anInterface, AuditRequest settings) {
        return new ResponseEntity<>(
                findProjectVulnerabilityAuditService.getInterfaceHistory(
                        anInterface,
                        settings.getLocation(),
                        createOrGetVulnerabilityService.createOrGetVulnerability(settings.getVulnerability()
                        )
                ), HttpStatus.OK);
    }

    public ResponseEntity<List<VulnerabiltyAudit>> getAuditForProjectVulnerability(Project project) {
        return new ResponseEntity<>(
                findProjectVulnerabilityAuditService.getProjectHistory(
                        project
                ), HttpStatus.OK);
    }

    public ResponseEntity<ProjectAudit> getAuditForProjectVulnerabilitySummarize(Project project) throws ParseException {
        return new ResponseEntity<>(
                findProjectVulnerabilityAuditService.getProjectAudit(
                        project
                ), HttpStatus.OK);
    }
}
