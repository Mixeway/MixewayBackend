package io.mixeway.domain.service.project;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.projection.VulnerableProjects;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.ProjectVulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class FindProjectService {

    private final ProjectRepository projectRepository;
    private final ProjectVulnerabilityRepository projectVulnerabilityRepository;

    public Optional<Project> findProjectByCiid(String ciid) {
        Optional<List<Project>> projects = projectRepository.findByCiid(ciid);
        if (projects.isPresent() && projects.get().size() > 0){
            return Optional.of(projects.get().get(0));
        } else {
            return Optional.empty();
        }
    }
    public Optional<Project> findProjectByName(String name) {
        Optional<List<Project>> projects = projectRepository.findByName(name);
        if (projects.isPresent() && projects.get().size() > 0) {
            return Optional.of(projects.get().get(0));
        } else {
            return Optional.empty();
        }
    }
    public Optional<Project> findProjectById(Long id) {
        Optional<Project> projects = projectRepository.findById(id);
        return projects;
    }
    public List<Project> findProjectsWithAutoCodeScan() {
        return projectRepository.findByAutoCodeScan(true);
    }
    public List<Project> findProjectsWithAutoWebAppScan(){
        return projectRepository.findByAutoWebAppScan(true);
    }

    public List<Project> findProjectsWithAutoInfraScan() {
        return projectRepository.findByAutoInfraScan(true);
    }

    public List<Project> findProjectsWithInfraScanRunning(){
        return projectRepository.getProjectWithInterfaceRunning();
    }
    public List<Project> findAll() {
        return projectRepository.findAll();
    }

    public Optional<Project> getProjectByName(String projectName) {
        return projectRepository.getProjectByName(projectName);
    }

    public Long count() {
        return projectRepository.count();
    }

    public List<String> getUniqueContactListEmails() {
        return projectRepository.getUniqueContactListEmails();
    }

    public List<Project> getUniqueContactListEmails(String email) {
        return projectRepository.getUniqueContactListEmails(email);
    }

    public List<Project> findProjectWithoutCodeVulnerabilities(){
        return projectRepository.getProjectsWithoutCodeVulns();
    }
    public List<Project> findProjectWithInterfaceWithScanRunning(){
        List<Long> projectIds = projectRepository.getProjectIdWithScanRunningOnInterface();
        List<Project> projects = new ArrayList<>();
        for (Long id : projectIds){
            Optional<Project> project = findProjectById(id);
            project.ifPresent(projects::add);
        }
        return projects;
    }
    public HashMap<Project, Long> findTop10ProjectsWithVulnerabilities(){
        HashMap<Project, Long> projects = new HashMap<>();
        for (VulnerableProjects vulnerableProject : projectVulnerabilityRepository.top10VulnerableProjects()) {
            projects.put(findProjectById(vulnerableProject.getId()).get(), vulnerableProject.getCount());
        }
        return projects;
    }
}
