package io.mixeway.api.project.service;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.rest.project.model.SoftVuln;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class OpenSourceService {
    private final ProjectRepository projectRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final PermissionFactory permissionFactory;
    private final VulnTemplate vulnTemplate;
    OpenSourceService(ProjectRepository projectRepository,
                      CodeProjectRepository codeProjectRepository,
                      VulnTemplate vulnTemplate,
                      PermissionFactory permissionFactory){
        this.projectRepository = projectRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.permissionFactory = permissionFactory;
        this.vulnTemplate = vulnTemplate;
    }

    public ResponseEntity<List<SoftVuln>> showSoft(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        List<SoftVuln> softVulns = new ArrayList<>();
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())){
            for (CodeProject cp : codeProjectRepository.findByCodeGroupIn(project.get().getCodes())){
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
