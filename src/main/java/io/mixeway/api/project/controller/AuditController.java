package io.mixeway.api.project.controller;

import io.mixeway.api.project.service.AuditService;
import io.mixeway.db.entity.NodeAudit;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/v2/api/show/project")
public class AuditController {

    private final AuditService auditService;

    AuditController(AuditService auditService){
        this.auditService = auditService;
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/audit")
    public ResponseEntity<List<NodeAudit>> showAudit(@PathVariable("id")Long id, Principal principal) {
        return auditService.showAudit(id, principal);
    }

}
