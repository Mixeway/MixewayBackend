package io.mixeway.domain.service.project;

import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class FindProjectService {

    private final ProjectRepository projectRepository;

    @Autowired
    public FindProjectService(ProjectRepository projectRepository) {
        this.projectRepository = projectRepository;
    }

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
}
