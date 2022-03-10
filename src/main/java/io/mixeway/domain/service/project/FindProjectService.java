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

    public Optional<Long> findProjectIdByCiid(String ciid) {
        Optional<List<Project>> projects = projectRepository.findByCiid(ciid);
        if (projects.isPresent() && projects.get().size() > 0){
            return Optional.of(projects.get().get(0).getId());
        } else {
            return Optional.empty();
        }
    }
    public Optional<Long> findProjectIdByName(String name) {
        Optional<List<Project>> projects = projectRepository.findByName(name);
        if (projects.isPresent() && projects.get().size() > 0) {
            return Optional.of(projects.get().get(0).getId());
        } else {
            return Optional.empty();
        }
    }
}
