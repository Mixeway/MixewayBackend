package io.mixeway.domain.service.cioperations;

import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.db.entity.CiOperations;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.domain.service.project.FindProjectService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindCiOperationsService {
    private final CiOperationsRepository ciOperationsRepository;
    private final FindProjectService findProjectService;

    public List<OverAllVulnTrendChartData> getVulnTrendData(List<Project> projects){
        return ciOperationsRepository.getCiTrend(projects.stream().map(Project::getId).collect(Collectors.toList()));
    }

    public Long countByResultAndProject(String result, List<Project> projects){
        return ciOperationsRepository.countByResultAndProjectIn(result, projects);
    }
    public List<CiOperations> findByProjects(List<Project>projects){
        return ciOperationsRepository.findByProjectInOrderByInsertedDesc(projects);
    }
    public Optional<CiOperations> findByCodeProjectAndCommitId(CodeProject codeProject, String commitId){
        return ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,commitId);
    }
    public List<CiOperations> findTop20(Project project){
        return ciOperationsRepository.findTop20ByProjectOrderByIdDesc(project);
    }
}
