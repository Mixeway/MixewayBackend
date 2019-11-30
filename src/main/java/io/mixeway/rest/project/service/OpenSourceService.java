package io.mixeway.rest.project.service;

import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeProjectRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.SoftwarePacketVulnerability;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SoftwarePacketVulnerabilityRepository;
import io.mixeway.rest.project.model.SoftVuln;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class OpenSourceService {
    private final ProjectRepository projectRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;
    OpenSourceService(ProjectRepository projectRepository,
                      CodeProjectRepository codeProjectRepository,
                      SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository){
        this.projectRepository = projectRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.softwarePacketVulnerabilityRepository = softwarePacketVulnerabilityRepository;
    }

    public ResponseEntity<List<SoftVuln>> showSoft(Long id) {
        Optional<Project> project = projectRepository.findById(id);
        List<SoftVuln> softVulns = new ArrayList<>();
        if (project.isPresent()){
            for (CodeProject cp : codeProjectRepository.findByCodeGroupIn(project.get().getCodes())){
                List<SoftwarePacketVulnerability> softwarePacketVulnerabilities = softwarePacketVulnerabilityRepository.getSoftwareVulnsForCodeProject(cp.getId());
                for (SoftwarePacketVulnerability spv : softwarePacketVulnerabilities){
                    SoftVuln softVuln = new SoftVuln();
                    softVuln.setCodeProject(cp);
                    softVuln.setSoftwarePacketVulnerability(spv);
                    softVulns.add(softVuln);
                }
            }
            return new ResponseEntity<>(softVulns, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.NOT_FOUND);
        }
    }
}
