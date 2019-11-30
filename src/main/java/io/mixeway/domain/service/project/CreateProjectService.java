package io.mixeway.domain.service.project;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;

@Service
public class CreateProjectService {

    private final ProjectRepository projectRepository;

    @Autowired
    public CreateProjectService(ProjectRepository projectRepository) {
        this.projectRepository = projectRepository;
    }

    @Transactional
    public Long createProject(String projectName, String ciid) {
        Project project = new Project();
        project.setName(projectName);
        project.setCiid(ciid);
        return projectRepository.save(project).getId();
    }

    @Transactional
    public boolean putProject(String projectName, String projectDescription, String ciid){
        try {
            Project p = new Project();
            p.setName(projectName);
            p.setDescription(projectDescription);
            p.setCiid(ciid);
            projectRepository.save(p);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
