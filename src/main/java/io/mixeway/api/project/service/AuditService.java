package io.mixeway.api.project.service;

import io.mixeway.db.entity.Node;
import io.mixeway.db.entity.NodeAudit;
import io.mixeway.db.entity.Project;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.utils.PermissionFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuditService {
    private final PermissionFactory permissionFactory;
    private final FindProjectService findProjectService;

    public ResponseEntity<List<NodeAudit>> showAudit(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())){
            List<NodeAudit> audit = new ArrayList<>();
            for (Node node : project.get().getNodes()) {
                audit.addAll(node.getNodeAudits());
            }
            return new ResponseEntity<>(audit, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

}
