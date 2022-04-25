package io.mixeway.domain.service.project;

import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class DeleteProjectService {
    private final ProjectRepository projectRepository;

    public void delete(Project project){
        projectRepository.delete(project);
    }
}
