package io.mixeway.rest.project.controller;

import io.mixeway.db.entity.Project;
import io.mixeway.rest.project.model.ApiKeyResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import io.mixeway.pojo.Status;
import io.mixeway.rest.project.service.ApiAccessService;

import java.security.*;

@Controller
@RequestMapping("/v2/api/show/project")
public class ApiAccessController {
    private final ApiAccessService apiAccessService;

    ApiAccessController(ApiAccessService apiAccessService){
        this.apiAccessService = apiAccessService;
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/apikey")
    public ResponseEntity<ApiKeyResponse> generateApiKey(@PathVariable("id")Long id, Principal principal) {
        return apiAccessService.generateApiKey(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/{id}/apikey")
    public ResponseEntity<Status> deleteApiKey(@PathVariable("id")Long id, Principal principal)  {
        return apiAccessService.deleteApiKey(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/{id}/apikey")
    public ResponseEntity<ApiKeyResponse> getApiKey(@PathVariable("id")Long id, Principal principal) {
        return apiAccessService.getApiKey(id, principal);
    }
}
