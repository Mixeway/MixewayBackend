package io.mixeway.domain.service.project;

import io.mixeway.api.dashboard.model.Projects;
import io.mixeway.api.project.model.ContactList;
import io.mixeway.api.project.model.VulnAuditorSettings;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.scanmanager.model.NetworkScanRequestModel;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

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

    public void updateWithRequest(NetworkScanRequestModel req, Project project){
        if (req.getEnableVulnManage().isPresent()) {
            req.getEnableVulnManage().get();
            project.setEnableVulnManage(req.getEnableVulnManage().get());
        }
        project.setName(req.getProjectName());
        projectRepository.save(project);
    }

    public Project setApiKey(Project project) {
        project.setApiKey(UUID.randomUUID().toString());
        return projectRepository.save(project);
    }

    public void deleteApiKey(Project project) {
        project.setApiKey(null);
        projectRepository.save(project);
    }

    public void enableInfraAutoScan(Project project) {
        project.setAutoInfraScan(true);
        projectRepository.save(project);
    }

    public void disableInfraAutoScan(Project project) {
        project.setAutoInfraScan(false);
        projectRepository.save(project);
    }

    public void enableCodeAutoScan(Project project) {
        project.setAutoCodeScan(true);
        projectRepository.save(project);
    }
    public void disableCodeAutoScan(Project project) {
        project.setAutoCodeScan(false);
        projectRepository.save(project);
    }

    public void updateContactList(Project project, ContactList contactList) {
        project.setContactList(contactList.getContactList());
        projectRepository.save(project);
    }

    public void setVulnAuditor(Project project, VulnAuditorSettings settings) {
        project.setVulnAuditorEnable(settings.isEnableVulnAuditor());
        if (StringUtils.isNotBlank(settings.getAppClient()))
            project.setAppClient(settings.getAppClient());
        if (StringUtils.isNotBlank(settings.getDclocation()))
            project.setNetworkdc(settings.getDclocation());
        projectRepository.save(project);
    }

    public void enableWebAppAutoScan(Project project) {
        project.setAutoWebAppScan(true);
        project.setWebAppAutoDiscover(true);
        projectRepository.save(project);
    }

    public void disableWebAppAutoScan(Project project) {
        project.setAutoWebAppScan(false);
        project.setWebAppAutoDiscover(false);
        projectRepository.save(project);
    }

    public void setRisk(Project p, int risk) {
        p.setRisk(Math.min(risk, 100));
        projectRepository.save(p);
    }
}
