package io.mixeway.domain.service.project;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;

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
        return Optional.of(projects.get().get(0).getId());
    }
    public Optional<Long> findProjectIdByName(String name) {
        Optional<List<Project>> projects = projectRepository.findByName(name);
        return Optional.of(projects.get().get(0).getId());
    }
}
