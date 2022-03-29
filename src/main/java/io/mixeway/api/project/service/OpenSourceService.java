package io.mixeway.api.project.service;

import io.mixeway.api.project.model.SoftVuln;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.utils.PermissionFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@Log4j2
@RequiredArgsConstructor
public class OpenSourceService {
    private final PermissionFactory permissionFactory;
    private final VulnTemplate vulnTemplate;
    private final FindProjectService findProjectService;
    private final FindCodeProjectService findCodeProjectService;

    public ResponseEntity<List<SoftVuln>> showSoft(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        List<SoftVuln> softVulns = new ArrayList<>();
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())){
            for (CodeProject cp : findCodeProjectService.findByProject(project.get())){
                List<ProjectVulnerability> softwarePacketVulnerabilities = vulnTemplate.projectVulnerabilityRepository.getSoftwareVulnsForCodeProject(cp.getId());
                for (ProjectVulnerability spv : softwarePacketVulnerabilities){
                    SoftVuln softVuln = new SoftVuln();
                    softVuln.setCodeProject(cp);
                    softVuln.setSoftwarePacketVulnerability(spv);
                    softVulns.add(softVuln);
                }
            }
            return new ResponseEntity<>(softVulns, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
}
