package io.mixeway.domain.service.project;

import io.mixeway.api.dashboard.model.Projects;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class UpdateProjectService {
    private final ProjectRepository projectRepository;

    public void update(Project project, Projects projectObject){
        project.setName(projectObject.getName());
        project.setDescription(projectObject.getDescription());
        project.setCiid(projectObject.getCiid());
        project.setEnableVulnManage(projectObject.getEnableVulnManage() == 1);
        projectRepository.save(project);
    }
}
