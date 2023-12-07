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
        createInfraVulnHistory(project, vulnHistory);
        createWebAppVulnHistory(project, vulnHistory);
        createCodeVulnHistory(project, codeSources, vulnHistory);
        createSCAVulnHistory(project, scaSources, vulnHistory);
        createAdditionalInfo(project, vulnHistory);



        vulnHistory.setAuditVulnHistory(createAuditHistory(project));

        vulnHistory.setProject(project);
        vulnHistory.setInserted(format.format(new Date()));
        vulnHistoryRepository.save(vulnHistory);
    }

    private void createAdditionalInfo(Project project, VulnHistory vulnHistory) {
        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByProject(project).collect(Collectors.toList());
        int detectedVulnerabilities = projectVulnerabilities.size();
        long detectedCriticalVulnerabilities = projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.API_SEVERITY_CRITICAL)).count();
        long resolvedCriticalVulnerabilities = projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.API_SEVERITY_CRITICAL) && Objects.equals(pv.getStatus().getId(), vulnTemplate.STATUS_REMOVED.getId()) && pv.getGrade()!=0).count();
        long acknowlegedVulnerabilities = projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.API_SEVERITY_CRITICAL) && pv.getGrade() == 0).count();
        resolvedCriticalVulnerabilities += acknowlegedVulnerabilities;
        List<ProjectVulnerability> solvedVulnerabilities = projectVulnerabilities.stream().filter(pv -> pv.getStatus().getId().equals(vulnTemplate.STATUS_REMOVED.getId())).collect(Collectors.toList());
        int percentResolvedCritical = (int) Math.ceil(((double) resolvedCriticalVulnerabilities / detectedCriticalVulnerabilities) * 100);
        int avgTimeToFix= (int) Math.ceil(calculateAverageDifferenceInDays(solvedVulnerabilities));
        vulnHistory.setAvgTimeToFix((long)avgTimeToFix);
        vulnHistory.setPercentResolvedCriticals((long)percentResolvedCritical);
        vulnHistory.setResolvedVulnerabilities(projectVulnerabilities.stream().filter(pv -> pv.getStatus().getId().equals(vulnTemplate.STATUS_REMOVED.getId())).count());

    }
    private static double calculateAverageDifferenceInDays(List<ProjectVulnerability> list) {
        if (list == null || list.isEmpty()) {
            // Handle this case as per your requirements, could throw an exception or return 0
            return 0;
        }

        long sumOfDifferences = 0;
        for (ProjectVulnerability pv : list) {
            sumOfDifferences += pv.calculateDifferenceInDays();
        }

        // Calculate the average
        return sumOfDifferences / (double) list.size();
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
    private void createWebAppVulnHistory(Project p, VulnHistory vulnHistory){
        List<ProjectVulnerability> webAppVulns = vulnTemplate.projectVulnerabilityRepository
                .findByWebAppInAndVulnerabilitySource(new ArrayList<>(p.getWebapps()),vulnTemplate.SOURCE_WEBAPP).stream().filter(pv -> pv.getGrade()!=0 && !pv.getStatus().getId().equals(vulnTemplate.STATUS_REMOVED.getId())).collect(Collectors.toList());
        vulnHistory.setWebAppVulnHistory(webAppVulns.stream().filter(pv -> severities.contains(pv.getSeverity())).count());
        vulnHistory.setWebAppCritVuln(webAppVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count());
        vulnHistory.setWebAppHighVuln(webAppVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count());
        vulnHistory.setWebAppMediumVuln(webAppVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count());
        vulnHistory.setWebAppLowVuln(webAppVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count());
    }

    /**
     * As Code Vuln we assume vulnerabilities detected by:
     * SAST
     * IaC
     * GitLeaks
     *
     */
    private void createCodeVulnHistory(Project p, List<VulnerabilitySource> list, VulnHistory vulnHistory){

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

        vulnHistory.setCodeVulnHistory((long)uniqueVulns.size());
        vulnHistory.setCodeCritVuln(uniqueVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count());
        vulnHistory.setCodeHighVuln(uniqueVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count());
        vulnHistory.setCodeMediumVuln(uniqueVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count());
        vulnHistory.setCodeLowVuln(uniqueVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count());
    }

    private void createSCAVulnHistory(Project p, List<VulnerabilitySource> list, VulnHistory vulnHistory){

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

        vulnHistory.setSoftwarePacketVulnNumber((long)uniqueVulns.size());
        vulnHistory.setScaCritVuln(uniqueVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count());
        vulnHistory.setScaHighVuln(uniqueVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count());
        vulnHistory.setScaMediumVuln(uniqueVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count());
        vulnHistory.setScaLowVuln(uniqueVulns.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count());
    }
    private VulnHistory createInfraVulnHistory(Project p, VulnHistory vulnHistory){
        List<ProjectVulnerability> infraVulns =vulnTemplate.projectVulnerabilityRepository.findByProjectAndVulnerabilitySourceAndSeverityInAndStatusNot(p, vulnTemplate.SOURCE_NETWORK, severities, vulnTemplate.STATUS_REMOVED).stream().filter(pv -> pv.getGrade()!=0).collect(Collectors.toList());
        vulnHistory.setInfrastructureVulnHistory((long)infraVulns.size());
        vulnHistory.setAssetCritVuln(infraVulns.stream().filter(pv-> pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count());
        vulnHistory.setAssetHighVuln(infraVulns.stream().filter(pv-> pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count());
        vulnHistory.setAssetMediumVuln(infraVulns.stream().filter(pv-> pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count());
        vulnHistory.setAssetLowVuln(infraVulns.stream().filter(pv-> pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count());
        return vulnHistory;
    }

    private Long createAuditHistory(Project p){
        return (long)(nodeAuditRepository.findByNodeInAndScoreIn(p.getNodes(),scores).size());
    }


}
