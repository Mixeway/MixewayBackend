package io.mixeway.domain.service.project;

import io.mixeway.pojo.PermissionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;

import java.security.Principal;

@Service
public class CreateProjectService {

    private final ProjectRepository projectRepository;
    private final PermissionFactory permissionFactory;

    @Autowired
    public CreateProjectService(ProjectRepository projectRepository, PermissionFactory permissionFactory) {
        this.projectRepository = projectRepository;
        this.permissionFactory = permissionFactory;
    }

    @Transactional
    public Long createProject(String projectName, String ciid, Principal principal) {
        Project project = new Project();
        project.setName(projectName);
        project.setCiid(ciid);
        project.setOwner(permissionFactory.getUserFromPrincipal(principal));
        project = projectRepository.save(project);
        permissionFactory.grantPermissionToProjectForUser(project,principal);
        return project.getId();
    }

    @Transactional
    public boolean putProject(String projectName, String projectDescription, String ciid, int enableVulnManage, Principal principal){
        try {
            Project p = new Project();
            p.setName(projectName);
            p.setDescription(projectDescription);
            p.setEnableVulnManage(enableVulnManage == 1);
            p.setCiid(ciid);
            p.setOwner(permissionFactory.getUserFromPrincipal(principal));
            p = projectRepository.save(p);
            permissionFactory.grantPermissionToProjectForUser(p, principal);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
