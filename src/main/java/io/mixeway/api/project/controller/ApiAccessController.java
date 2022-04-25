package io.mixeway.api.project.controller;

import io.mixeway.api.project.model.ApiKeyResponse;
import io.mixeway.api.project.service.ApiAccessService;
import io.mixeway.utils.Status;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

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
