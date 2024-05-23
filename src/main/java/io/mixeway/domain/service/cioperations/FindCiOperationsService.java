package io.mixeway.domain.service.cioperations;

import io.mixeway.api.cicd.model.ProjectMetadata;
import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.domain.exceptions.CodeProjectNotFoundException;
import io.mixeway.domain.exceptions.WebAppNotFoundException;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
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
    private final FindCodeProjectService findCodeProjectService;
    private final FindWebAppService findWebAppService;
    private final GetOrCreateCiOperationsService createCiOperationsService;

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
    public List<CiOperations> findTop20CodeProject(CodeProject codeProject){
        return ciOperationsRepository.findTop20ByCodeProjectOrderByIdDesc(codeProject);
    }
    public List<CiOperations> findTop20WebApp(WebApp webApp){
        return ciOperationsRepository.findTop20ByWebappOrderByIdDesc(webApp);
    }
    public List<CiOperations> findTop20Interface(Interface anInterface){
        return ciOperationsRepository.findTop20ByInterfaceObjOrderByIdDesc(anInterface);
    }
    public CiOperations findForProjectMetadata(ProjectMetadata projectMetadata) {
        if(projectMetadata.getCodeProjectId() > 0) {
            Optional<CodeProject> codeProject = findCodeProjectService.findById(projectMetadata.getCodeProjectId());
            if (!codeProject.isPresent()) {
                throw new CodeProjectNotFoundException("Cannot find codeProject with repoURL: " + projectMetadata.getTarget());
            } else {
                return createCiOperationsService.create(projectMetadata, codeProject.get());
            }
        } else if(projectMetadata.getWebAppId() > 0) {
            Optional<WebApp> webApp = findWebAppService.findById(projectMetadata.getWebAppId());
            if (!webApp.isPresent()) {
                throw new WebAppNotFoundException("Cannot find webApp with URL: " + projectMetadata.getTarget());
            } else {
                return createCiOperationsService.create(projectMetadata, webApp.get());
            }
        }
        return null;
    }
    public List<CiOperations> findCiOperations(Scannable scannable){
        if(scannable instanceof CodeProject){
            return ciOperationsRepository.findByCodeProject((CodeProject) scannable);
        }else if(scannable instanceof WebApp) {
            return ciOperationsRepository.findByWebapp((WebApp) scannable);
        }
        return new ArrayList<>();
    }
}
