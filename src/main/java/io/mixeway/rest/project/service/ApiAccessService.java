package io.mixeway.rest.project.service;

import io.mixeway.db.entity.Project;
import io.mixeway.rest.project.model.ApiKeyResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.pojo.Status;

import java.util.Optional;
import java.util.UUID;

@Service
public class ApiAccessService {
    private static final Logger log = LoggerFactory.getLogger(ApiAccessService.class);

    private final ProjectRepository projectRepository;

    @Autowired
    public ApiAccessService(ProjectRepository projectRepository){
        this.projectRepository = projectRepository;
    }

    public ResponseEntity<ApiKeyResponse> generateApiKey(Long id, String name) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            project.get().setApiKey(UUID.randomUUID().toString());
            projectRepository.save(project.get());
            log.info("{} - Generated new ApiKey {}", name, project.get().getName());
            return new ResponseEntity<>(new ApiKeyResponse(project.get().getApiKey()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> deleteApiKey(Long id, String name) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            project.get().setApiKey(null);
            projectRepository.save(project.get());
            log.info("{} - Deleted existing ApiKey {}", name, project.get().getName());
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<ApiKeyResponse> getApiKey(Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            return new ResponseEntity<>(new ApiKeyResponse(project.get().getApiKey()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
}
