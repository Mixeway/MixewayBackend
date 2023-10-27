package io.mixeway.domain.service.vulnhistory;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.NodeAuditRepository;
import io.mixeway.db.repository.VulnHistoryRepository;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;


/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class CreateVulnHistoryService {
    private final VulnHistoryRepository vulnHistoryRepository;
    private final VulnTemplate vulnTemplate;
    private final NodeAuditRepository nodeAuditRepository;
    private final FindCodeProjectService findCodeProjectService;

    private final List<String> severities = new ArrayList<String>(){{
        add("Medium" );
        add("High");
        add("Critical");
    }};
    private final List<String> scores = new ArrayList<String>(){{
        add("WARN" );
        add("FAIL");
    }};
    private final List<String> critSeverities = new ArrayList<String>(){{
        add("High");
        add("Critical");
    }};



    private DateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public void createScheduled(Project project){
        final List<VulnerabilitySource> codeSources = new ArrayList<VulnerabilitySource>(){{
            add(vulnTemplate.SOURCE_SOURCECODE);
            add(vulnTemplate.SOURCE_IAC);
            add(vulnTemplate.SOURCE_GITLEAKS);
        }};
        final List<VulnerabilitySource> scaSources = new ArrayList<VulnerabilitySource>(){{
            add(vulnTemplate.SOURCE_OPENSOURCE);
        }};

        VulnHistory vulnHistory = new VulnHistory();
        vulnHistory.setName(Constants.VULN_HISTORY_ALL);
        vulnHistory.setInfrastructureVulnHistory(createInfraVulnHistory(project));
        vulnHistory.setWebAppVulnHistory(createWebAppVulnHistory(project));
        vulnHistory.setCodeVulnHistory(createCodeVulnHistory(project, codeSources));
        vulnHistory.setAuditVulnHistory(createAuditHistory(project));
        vulnHistory.setSoftwarePacketVulnNumber(createCodeVulnHistory(project, scaSources));
        vulnHistory.setProject(project);
        vulnHistory.setInserted(format.format(new Date()));
        vulnHistoryRepository.save(vulnHistory);
    }
    public void create(Project project, String date, Long infra, Long webApp, Long code, Long audit, Long software){
        VulnHistory vulnHistory = new VulnHistory();
        vulnHistory.setName(Constants.VULN_HISTORY_ALL);
        vulnHistory.setInfrastructureVulnHistory(infra);
        vulnHistory.setWebAppVulnHistory(webApp);
        vulnHistory.setCodeVulnHistory(code);
        vulnHistory.setAuditVulnHistory(audit);
        vulnHistory.setSoftwarePacketVulnNumber(software);
        vulnHistory.setProject(project);
        vulnHistory.setInserted(date);
        vulnHistoryRepository.save(vulnHistory);
    }
    private Long createWebAppVulnHistory(Project p){
        return vulnTemplate.projectVulnerabilityRepository
                .findByWebAppInAndVulnerabilitySourceAndSeverityIn(new ArrayList<>(p.getWebapps()),vulnTemplate.SOURCE_WEBAPP, severities).count();

    }

    /**
     * As Code Vuln we assume vulnerabilities detected by:
     * SAST
     * IaC
     * GitLeaks
     *
     */
    private Long createCodeVulnHistory(Project p, List<VulnerabilitySource> list){

        List<Project> projects = Collections.singletonList(p);
        List<CodeProject> codeProjects = findCodeProjectService.getCodeProjectsInListOfProjects(projects);
        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findVulnerabilitiesForCode(codeProjects, list);
        projectVulnerabilities.removeIf(projectVulnerability -> projectVulnerability.getGrade() == 0);
        projectVulnerabilities.removeIf(projectVulnerability -> Objects.equals(projectVulnerability.getSeverity(), Constants.API_SEVERITY_LOW));
        projectVulnerabilities.removeIf(projectVulnerability -> Objects.equals(projectVulnerability.getSeverity(), Constants.API_SEVERITY_MEDIUM));
        projectVulnerabilities.removeIf(projectVulnerability -> Objects.equals(projectVulnerability.getSeverity(), Constants.API_SEVERITY_INFO));

        // Return only vulnerabilities in default branch
        Map<String, ProjectVulnerability> uniqueVulnsMap = new HashMap<>();

        for (ProjectVulnerability projectVulnerability : projectVulnerabilities) {
            CodeProjectBranch codeProjectBranch = projectVulnerability.getCodeProjectBranch();
            CodeProject codeProject = projectVulnerability.getCodeProject();

            if (codeProjectBranch != null && codeProject != null) {
                String branchName = codeProjectBranch.getName();
                String projectBranch = codeProject.getBranch();

                if (branchName != null && branchName.equals(projectBranch)) {
                    String uniqueKey = branchName + "_" + projectBranch + "_" + projectVulnerability.getId(); // Tworzenie unikalnego klucza
                    uniqueVulnsMap.put(uniqueKey, projectVulnerability);
                }
            }
        }

        List<ProjectVulnerability> uniqueVulns = new ArrayList<>(uniqueVulnsMap.values());

        return (long) uniqueVulns.size();
    }
    private Long createInfraVulnHistory(Project p){
        return getInfraVulnsForProject(p);
    }

    private Long createAuditHistory(Project p){
        return (long)(nodeAuditRepository.findByNodeInAndScoreIn(p.getNodes(),scores).size());
    }

    private long getInfraVulnsForProject(Project project){
        return vulnTemplate.projectVulnerabilityRepository.findByProjectAndVulnerabilitySourceAndSeverityInAndStatusNot(project, vulnTemplate.SOURCE_NETWORK, severities, vulnTemplate.STATUS_REMOVED).size();
    }
}
