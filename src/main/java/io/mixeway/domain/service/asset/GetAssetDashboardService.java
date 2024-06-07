package io.mixeway.domain.service.asset;

import io.mixeway.api.project.model.AssetDashboardModel;
import io.mixeway.api.project.model.AssetDashboardStatModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.domain.service.scanmanager.code.GetOrCreateCodeProjectBranchService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class GetAssetDashboardService {
    private final VulnTemplate vulnTemplate;

    public AssetDashboardModel buildDashboardModelForCodeProject(CodeProject codeProject) {
        if (codeProject == null) {
            throw new IllegalArgumentException("codeProject cannot be null");
        }
        if (vulnTemplate == null || vulnTemplate.projectVulnerabilityRepository == null) {
            throw new IllegalArgumentException("vulnTemplate or vulnTemplate.projectVulnerabilityRepository cannot be null");
        }

        List<ProjectVulnerability> allProjectVulnerabilities = vulnTemplate.projectVulnerabilityRepository
                .findByCodeProject(codeProject)
                .stream()
                .filter(pv -> pv != null && pv.getCodeProjectBranch() != null && pv.getCodeProjectBranch().getName().equals(codeProject.getBranch()))
                .collect(Collectors.toList());

        List<ProjectVulnerability> projectVulnerabilities = allProjectVulnerabilities.stream()
                .filter(pv -> pv != null && pv.getStatus() != null && !pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .filter(pv -> pv.getGrade() != 0)
                .collect(Collectors.toList());

        List<ProjectVulnerability> solvedVulnerabilities = allProjectVulnerabilities.stream()
                .filter(pv -> pv != null && pv.getStatus() != null && pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .collect(Collectors.toList());

        List<ProjectVulnerability> reviewedVulnerabilities = allProjectVulnerabilities.stream()
                .filter(pv -> pv != null && pv.getStatus() != null && !pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .filter(pv -> pv.getGrade() == 0 || pv.getGrade() == 1)
                .collect(Collectors.toList());

        List<ProjectVulnerability> notReviewedVulnerabilities = allProjectVulnerabilities.stream()
                .filter(pv -> pv != null && pv.getStatus() != null && !pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .filter(pv -> pv.getGrade() == -1)
                .collect(Collectors.toList());

        int allCrit = (int) projectVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count();
        int allHigh = (int) projectVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count();
        int allMedium = (int) projectVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count();
        int allLow = (int) projectVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count();

        int solvedCrit = (int) solvedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count();
        int solvedHigh = (int) solvedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count();
        int solvedMedium = (int) solvedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count();
        int solvedLow = (int) solvedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count();

        int reviewedCrit = (int) reviewedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count();
        int reviewedHigh = (int) reviewedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count();
        int reviewedMedium = (int) reviewedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count();
        int reviewedLow = (int) reviewedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count();

        int notReviewedCrit = (int) notReviewedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count();
        int notReviewedHigh = (int) notReviewedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count();
        int notReviewedMedium = (int) notReviewedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count();
        int notReviewedLow = (int) notReviewedVulnerabilities.stream().filter(pv -> pv != null && pv.getSeverity() != null && pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count();

        // Calculate average days for each severity level
        long avgCrit = calculateAverageDays(allProjectVulnerabilities, "Critical");
        long avgHigh = calculateAverageDays(allProjectVulnerabilities, "High");
        long avgMedium = calculateAverageDays(allProjectVulnerabilities, "Medium");
        long avgLow = calculateAverageDays(allProjectVulnerabilities, "Low");

        // Calculate average days for all vulnerabilities
        long avgAll = calculateAverageDays(allProjectVulnerabilities, null);
        int avgCritPercent = calculatePercentage(avgCrit);
        int avgHighPercent = calculatePercentage(avgHigh);
        int avgMediumPercent = calculatePercentage(avgMedium);
        int avgLowPercent = calculatePercentage(avgLow);

        AssetDashboardStatModel vulnStats = AssetDashboardStatModel.builder()
                .crit(allCrit)
                .high(allHigh)
                .medium(allMedium)
                .low(allLow)
                .build();

        AssetDashboardStatModel solvedIssues = AssetDashboardStatModel.builder()
                .crit(solvedCrit)
                .high(solvedHigh)
                .medium(solvedMedium)
                .low(solvedLow)
                .critPercent((solvedCrit + allCrit) == 0 ? 0 : (int) Math.ceil((solvedCrit / (double) (solvedCrit + allCrit) * 100)))
                .highPercent((solvedHigh + allHigh) == 0 ? 0 : (int) Math.ceil((solvedHigh / (double) (solvedHigh + allHigh) * 100)))
                .mediumPercent((solvedMedium + allMedium) == 0 ? 0 : (int) Math.ceil((solvedMedium / (double) (solvedMedium + allMedium)) * 100))
                .lowPercent((solvedLow + allLow) == 0 ? 0 : (int) Math.ceil((solvedLow / (double) (solvedLow + allLow)) * 100))
                .total(solvedVulnerabilities.size())
                .build();

        AssetDashboardStatModel reviewedIssues = AssetDashboardStatModel.builder()
                .crit(reviewedCrit)
                .high(reviewedHigh)
                .medium(reviewedMedium)
                .low(reviewedLow)
                .critPercent((reviewedCrit + notReviewedCrit) == 0 ? 0 : (int) Math.ceil((reviewedCrit / (double) (reviewedCrit + notReviewedCrit) * 100)))
                .highPercent((reviewedHigh + notReviewedHigh) == 0 ? 0 : (int) Math.ceil((reviewedHigh / (double) (reviewedHigh + notReviewedHigh) * 100)))
                .mediumPercent((reviewedMedium + notReviewedMedium) == 0 ? 0 : (int) Math.ceil((reviewedMedium / (double) (reviewedMedium + notReviewedMedium)) * 100))
                .lowPercent((reviewedLow + notReviewedLow) == 0 ? 0 : (int) Math.ceil((reviewedLow / (double) (reviewedLow + notReviewedLow)) * 100))
                .total(reviewedVulnerabilities.size())
                .build();

        AssetDashboardStatModel ttmIssues = AssetDashboardStatModel.builder()
                .crit((int) avgCrit)
                .high((int) avgHigh)
                .medium((int) avgMedium)
                .low((int) avgLow)
                .total((int) avgAll)
                .critPercent(avgCritPercent)
                .lowPercent(avgLowPercent)
                .highPercent(avgHighPercent)
                .mediumPercent(avgMediumPercent)
                .build();

        return AssetDashboardModel.builder()
                .assetName(codeProject.getName())
                .target(codeProject.getRepoUrl())
                .created(codeProject.getInserted().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")))
                .branch(codeProject.getBranch())
                .securityGateway("success")
                .reviewedIssues(reviewedIssues)
                .solvedIssues(solvedIssues)
                .timeToResolve(ttmIssues)
                .vulnerabilities(vulnStats)
                .build();
    }
    private long calculateAverageDays(List<ProjectVulnerability> vulnerabilities, String severity) {
        // Filter vulnerabilities based on severity (if provided)
        List<ProjectVulnerability> filteredVulns = vulnerabilities.stream()
                .filter(pv -> severity == null || pv.getSeverity().equals(severity))
                .filter(pv -> pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .collect(Collectors.toList());

        if (filteredVulns.isEmpty()) {
            return 0;
        }

        // Calculate total days for all vulnerabilities
        long totalDays = filteredVulns.stream()
                .mapToLong(pv -> Duration.between(pv.getCreated(), pv.getInserted()).toDays())
                .sum();

        // Calculate average days (rounding up to the nearest integer)
        return Math.round(Math.ceil((double) totalDays / filteredVulns.size()));
    }
    private int calculatePercentage(long avgDays) {
        if (avgDays == 0) {
            return 0;
        } else if (avgDays > 1 && avgDays < 3) {
            return 10;
        } else if (avgDays > 3 && avgDays <= 10) {
            return 30;
        } else if (avgDays > 10 && avgDays < 20) {
            return 70;
        } else {
            return 100;
        }
    }

    public AssetDashboardModel buildDashboardModel(List<ProjectVulnerability> allProjectVulnerabilities, String name, String target, LocalDateTime inserted) {

        List<ProjectVulnerability> projectVulnerabilities = allProjectVulnerabilities.stream()
                .filter(pv -> !pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .filter(pv -> pv.getGrade() != 0)
                .collect(Collectors.toList());
        List<ProjectVulnerability> solvedVulnerabilities = allProjectVulnerabilities.stream()
                .filter(pv -> pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .collect(Collectors.toList());
        List<ProjectVulnerability> reviewedVulnerabilities = allProjectVulnerabilities.stream()
                .filter(pv -> !pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .filter(pv -> pv.getGrade() == 0 || pv.getGrade() == 1)
                .collect(Collectors.toList());
        List<ProjectVulnerability> notReviewedVulnerabilities = allProjectVulnerabilities.stream()
                .filter(pv -> !pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName()))
                .filter(pv -> pv.getGrade() == -1)
                .collect(Collectors.toList());


        int allCrit = (int)projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count();
        int allHigh = (int)projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count();
        int allMedium = (int)projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count();
        int allLow = (int)projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count();

        int solvedCrit = (int)solvedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count();
        int solvedHigh = (int)solvedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count();
        int solvedMedium = (int)solvedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count();
        int solvedLow = (int)solvedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count();

        int reviewedCrit = (int)reviewedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count();
        int reviewedHigh = (int)reviewedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count();
        int reviewedMedium = (int)reviewedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count();
        int reviewedLow = (int)reviewedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count();

        int notReviewedCrit = (int)notReviewedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL)).count();
        int notReviewedHigh = (int)notReviewedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)).count();
        int notReviewedMedium = (int)notReviewedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM)).count();
        int notReviewedLow = (int)notReviewedVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW)).count();

        // Calculate average days for each severity level
        long avgCrit = calculateAverageDays(allProjectVulnerabilities, "Critical");
        long avgHigh = calculateAverageDays(allProjectVulnerabilities, "High");
        long avgMedium = calculateAverageDays(allProjectVulnerabilities, "Medium");
        long avgLow = calculateAverageDays(allProjectVulnerabilities, "Low");

        // Calculate average days for all vulnerabilities
        long avgAll = calculateAverageDays(allProjectVulnerabilities, null);
        int avgCritPercent = calculatePercentage(avgCrit);
        int avgHighPercent = calculatePercentage(avgHigh);
        int avgMediumPercent = calculatePercentage(avgMedium);
        int avgLowPercent = calculatePercentage(avgLow);




        AssetDashboardStatModel vulnStats = AssetDashboardStatModel.builder()
                .crit(allCrit)
                .high(allHigh)
                .medium(allMedium)
                .low(allLow)
                .build();

        AssetDashboardStatModel solvedIssues = AssetDashboardStatModel.builder()
                .crit(solvedCrit)
                .high(solvedHigh)
                .medium(solvedMedium)
                .low(solvedLow)
                .critPercent((solvedCrit + allCrit) == 0 ? 0 : (int) Math.ceil((solvedCrit / (double)(solvedCrit + allCrit) * 100)) )
                .highPercent((solvedHigh + allHigh) == 0 ? 0 : (int) Math.ceil((solvedHigh / (double)(solvedHigh + allHigh) * 100)) )
                .mediumPercent((solvedMedium + allMedium) == 0 ? 0 : (int) Math.ceil((solvedMedium / (double)(solvedMedium + allMedium)) * 100) )
                .lowPercent((solvedLow + allLow) == 0 ? 0 : (int) Math.ceil((solvedLow / (double)(solvedLow + allLow)) * 100))
                .total(solvedVulnerabilities.size())
                .build();
        AssetDashboardStatModel reviewedIssues = AssetDashboardStatModel.builder()
                .crit(reviewedCrit)
                .high(reviewedHigh)
                .medium(reviewedMedium)
                .low(reviewedLow)
                .critPercent((reviewedCrit + notReviewedCrit) == 0 ? 0 : (int) Math.ceil((reviewedCrit / (double)(reviewedCrit + notReviewedCrit) * 100)) )
                .highPercent((reviewedHigh + notReviewedHigh) == 0 ? 0 : (int) Math.ceil((reviewedHigh / (double)(reviewedHigh + notReviewedHigh) * 100)) )
                .mediumPercent((reviewedMedium + notReviewedMedium) == 0 ? 0 : (int) Math.ceil((reviewedMedium / (double)(reviewedMedium + notReviewedMedium)) * 100) )
                .lowPercent((reviewedLow + notReviewedLow) == 0 ? 0 : (int) Math.ceil((reviewedLow / (double)(reviewedLow + notReviewedLow)) * 100))
                .total(reviewedVulnerabilities.size())
                .build();

        AssetDashboardStatModel ttmIssues = AssetDashboardStatModel.builder()
                .crit((int)avgCrit)
                .high((int) avgHigh)
                .medium( (int) avgMedium)
                .low((int) avgLow)
                .total((int)avgAll)
                .critPercent(avgCritPercent)
                .lowPercent(avgLowPercent)
                .highPercent(avgHighPercent)
                .mediumPercent(avgMediumPercent)
                .build();

        return AssetDashboardModel.builder()
                .assetName(name)
                .target(target)
                .created(inserted.format(DateTimeFormatter.ofPattern("yyyy-MM-dd")))
                .securityGateway("success")
                .reviewedIssues(reviewedIssues)
                .solvedIssues(solvedIssues)
                .timeToResolve(ttmIssues)
                .vulnerabilities(vulnStats)
                .build();
    }
}
