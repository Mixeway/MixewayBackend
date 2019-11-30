package io.mixeway.rest.project.service;

import io.mixeway.db.entity.Project;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.entity.Node;
import io.mixeway.db.entity.NodeAudit;
import io.mixeway.db.repository.ProjectRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class AuditService {
    private final ProjectRepository projectRepository;

    @Autowired
    AuditService(ProjectRepository projectRepository){
        this.projectRepository = projectRepository;
    }

    public ResponseEntity<List<NodeAudit>> showAudit(Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            List<NodeAudit> audit = new ArrayList<>();
            for (Node node : project.get().getNodes()) {
                audit.addAll(node.getNodeAudits());
            }
            return new ResponseEntity<>(audit, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

}
