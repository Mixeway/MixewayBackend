package io.mixeway.domain.service.project;

import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;

@Service
public class GetProjectsService {
    private final ProjectRepository projectRepository;

    @Autowired
    GetProjectsService(ProjectRepository projectRepository){
        this.projectRepository = projectRepository;
    }

    public List<Project> getProjects() throws IOException {

        return projectRepository.findAll();
    }

    public Project getProject(long id){
        return projectRepository.findById(id).orElse(null);
    }
}
