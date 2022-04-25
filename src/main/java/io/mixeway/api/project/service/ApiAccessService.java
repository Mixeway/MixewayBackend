package io.mixeway.api.project.service;

import io.mixeway.api.project.model.ApiKeyResponse;
import io.mixeway.db.entity.Project;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.UpdateProjectService;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.Optional;

@Service
@Log4j2
@RequiredArgsConstructor
public class ApiAccessService {
    private final PermissionFactory permissionFactory;
    private final FindProjectService findProjectService;
    private final UpdateProjectService updateProjectService;


    public ResponseEntity<ApiKeyResponse> generateApiKey(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Project project1 = updateProjectService.setApiKey(project.get());

            log.info("{} - Generated new ApiKey {}", principal.getName(), project1.getName());
            return new ResponseEntity<>(new ApiKeyResponse(project1.getApiKey()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> deleteApiKey(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            updateProjectService.deleteApiKey(project.get());
            log.info("{} - Deleted existing ApiKey {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<ApiKeyResponse> getApiKey(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            return new ResponseEntity<>(new ApiKeyResponse(project.get().getApiKey()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
}
