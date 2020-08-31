package io.mixeway.rest.project.service;

import io.mixeway.db.entity.Project;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.rest.project.model.ApiKeyResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.pojo.Status;

import java.security.Principal;
import java.util.Optional;
import java.util.UUID;

@Service
public class ApiAccessService {
    private static final Logger log = LoggerFactory.getLogger(ApiAccessService.class);

    private final ProjectRepository projectRepository;
    private final PermissionFactory permissionFactory;

    public ApiAccessService(ProjectRepository projectRepository, PermissionFactory permissionFactory){
        this.projectRepository = projectRepository;
        this.permissionFactory = permissionFactory;
    }

    public ResponseEntity<ApiKeyResponse> generateApiKey(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            project.get().setApiKey(UUID.randomUUID().toString());
            projectRepository.save(project.get());
            log.info("{} - Generated new ApiKey {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(new ApiKeyResponse(project.get().getApiKey()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> deleteApiKey(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            project.get().setApiKey(null);
            projectRepository.save(project.get());
            log.info("{} - Deleted existing ApiKey {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<ApiKeyResponse> getApiKey(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            return new ResponseEntity<>(new ApiKeyResponse(project.get().getApiKey()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
}
