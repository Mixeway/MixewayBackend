package io.mixeway.api.project.controller;

import io.mixeway.api.project.model.SoftVuln;
import io.mixeway.api.project.service.OpenSourceService;
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
public class OpenSourceController {
    private final OpenSourceService openSourceService;

    OpenSourceController(OpenSourceService openSourceService){
        this.openSourceService = openSourceService;
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/{id}/vulns/soft")
    public ResponseEntity<List<SoftVuln>> showSoft(@PathVariable("id")Long id, Principal principal) {
        return openSourceService.showSoft(id, principal);
    }

}
