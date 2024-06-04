package io.mixeway.domain.service.metric;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.MetricRepository;
import io.mixeway.domain.service.bugtracker.FindBugTrackerService;
import io.mixeway.domain.service.cioperations.FindCiOperationsService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MetricService {
    private final VulnTemplate vulnTemplate;
    private final FindProjectService findProjectService;
    private final FindCiOperationsService findCiOperationsService;
    private final FindBugTrackerService findBugTrackerService;
    private final FindMetricService findMetricService;
    private final MetricRepository metricRepository;

    public void getGlobalMetric() {
        Metric globalMetric = findMetricService.getGlobalMetric();

        List<Project> allProjects = findProjectService.findAll();
        List<ProjectVulnerability> projectVulnerabilities = getAllVulnerabilities();
        List<CiOperations> ciOperations = findCiOperationsService.findAll();
        List<BugTracker> bugTrackers = findBugTrackerService.findAll();

        buildMetric(projectVulnerabilities, ciOperations, allProjects, bugTrackers, globalMetric);
    }

    public void getProjectMetric(Project project) {
        List<Project> allProjects = new ArrayList<>();
        allProjects.add(project);
        Metric projectMetric = findMetricService.getProjectMetric(project);

        List<ProjectVulnerability> projectVulnerabilities = getProjectVulnerabilities(project);
        List<CiOperations> ciOperations = findCiOperationsService.findByProject(project);
        List<BugTracker> bugTrackers = findBugTrackerService.findByProject(project);

        buildMetric(projectVulnerabilities, ciOperations, allProjects, bugTrackers, projectMetric);
    }

    void buildMetric(List<ProjectVulnerability> projectVulnerabilities, List<CiOperations> ciOperations,
                     List<Project> allProjects, List<BugTracker> bugTrackers, Metric globalMetric) {
        int totalProjects = allProjects.size();

        long activeVuln = projectVulnerabilities.stream()
                .filter(pv -> pv.getGrade() != 0)
                .filter(pv -> !pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .count();

        int activeVulnPercent = calculateAverage(activeVuln, totalProjects);

        long fixedVulns = projectVulnerabilities.stream()
                .filter(pv -> pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .count();

        long totalVulns = projectVulnerabilities.stream()
                .filter(pv -> pv.getGrade() != 0)
                .count();

        int fixedVulnsPercent = calculatePercentage(fixedVulns, totalVulns);

        double averageFixTime = projectVulnerabilities.stream()
                .filter(pv -> pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .mapToLong(pv -> ChronoUnit.DAYS.between(pv.getCreated(), pv.getInserted()))
                .average()
                .orElse(0);

        Set<Project> distinctProjects = ciOperations.stream()
                .map(CiOperations::getProject)
                .collect(Collectors.toSet());
        int numberOfDistinctProjects = distinctProjects.size();
        int percentProjectsWithCiOps = calculatePercentage(numberOfDistinctProjects, totalProjects);

        long ciOpsWithResultOk = ciOperations.stream()
                .filter(ciOp -> "Ok".equalsIgnoreCase(ciOp.getResult()))
                .count();
        int ratioCiOpsWithResultOk = calculatePercentage(ciOpsWithResultOk, ciOperations.size());

        Set<Project> distinctProjectsBugTrackers = bugTrackers.stream()
                .map(BugTracker::getProject)
                .collect(Collectors.toSet());
        int numberOfDistinctProjectsBugTracker = distinctProjectsBugTrackers.size();
        int ratioOfProjectWithBugTracking = calculatePercentage(numberOfDistinctProjectsBugTracker, totalProjects);

        globalMetric.setActiveVulnNo((int) activeVuln);
        globalMetric.setActiveVulnAvg(activeVulnPercent);
        globalMetric.setFixedVulnNo((int) fixedVulns);
        globalMetric.setFixedVulnPercent(fixedVulnsPercent);
        globalMetric.setFixTime((int) Math.ceil(averageFixTime));
        globalMetric.setProjectWithCicdNo(numberOfDistinctProjects);
        globalMetric.setProjectWithCicdPercent((int) Math.ceil(percentProjectsWithCiOps));
        globalMetric.setSecureJobNo((int) ciOpsWithResultOk);
        globalMetric.setSecureJobPercent((int) Math.ceil(ratioCiOpsWithResultOk));
        globalMetric.setBugTrackingIntegratedNo(numberOfDistinctProjectsBugTracker);
        globalMetric.setBugTrackingIntegratedPercent((int) Math.ceil(ratioOfProjectWithBugTracking));

        metricRepository.saveAndFlush(globalMetric);
    }

    int calculatePercentage(long part, long total) {
        return total == 0 ? 0 : (int) Math.ceil((double) part / total * 100);
    }
    int calculateAverage(long part, long total) {
        return total == 0 ? 0 : (int) Math.ceil((double) part / total );
    }

    public List<ProjectVulnerability> getAllVulnerabilities() {
        List<ProjectVulnerability> vulnerabilities = vulnTemplate.projectVulnerabilityRepository.findAll();
        return vulnerabilities.stream()
                .filter(this::isNotDuplicate)
                .collect(Collectors.toList());
    }
    public List<ProjectVulnerability> getProjectVulnerabilities(Project project) {
        List<ProjectVulnerability> vulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByProject(project).collect(Collectors.toList());
        return vulnerabilities.stream()
                .filter(this::isNotDuplicate)
                .collect(Collectors.toList());
    }

    boolean isNotDuplicate(ProjectVulnerability vulnerability) {
        List<ProjectVulnerability> vulnerabilities = vulnTemplate.projectVulnerabilityRepository.findAll();
        return vulnerabilities.stream()
                .noneMatch(v -> isDuplicate(v, vulnerability));
    }

    boolean isDuplicate(ProjectVulnerability v1, ProjectVulnerability v2) {
        if (v1 == v2) return false;  // Skip self-comparison
        if (v1.getCodeProject() != null && v1.getCodeProjectBranch() != null
                && v2.getCodeProject() != null && v2.getCodeProjectBranch() != null) {
            return v1.getSeverity().equals(v2.getSeverity())
                    && v1.getLocation().equals(v2.getLocation())
                    && v1.getVulnerability().equals(v2.getVulnerability())
                    && v1.getCodeProjectBranch().getName().equals(v2.getCodeProjectBranch().getName());
        }
        return false;
    }
}