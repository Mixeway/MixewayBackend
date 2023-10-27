package io.mixeway.api.statistic.service;

import io.mixeway.api.vulnmanage.model.GlobalStatistic;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.CisRequirement;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.Vulnerability;
import io.mixeway.db.projection.VulnBarChartProjection;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.projectvulnerability.GetProjectVulnerabilitiesService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections.ArrayStack;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class VulnsService {
    private final VulnTemplate vulnTemplate;
    private final PermissionFactory permissionFactory;
    private final FindProjectService findProjectService;
    private final GetProjectVulnerabilitiesService getProjectVulnerabilitiesService;


    public ResponseEntity<List<VulnBarChartProjection>> getCodeVulnsTop(Principal principal) {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository
                .top10CodeVulns(
                        permissionFactory
                                .getProjectForPrincipal(principal)
                                .stream()
                                .map(Project::getId)
                                .collect(Collectors.toList())),
                HttpStatus.OK);
    }

    public ResponseEntity<List<VulnBarChartProjection>> getCodeProjectsTop(Principal principal) {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10CodeProjects(permissionFactory
                .getProjectForPrincipal(principal)
                .stream()
                .map(Project::getId)
                .collect(Collectors.toList())), HttpStatus.OK);
    }

    public ResponseEntity<List<VulnBarChartProjection>> getInfraVulnsTop(Principal principal) {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10InfraVulns(permissionFactory
                .getProjectForPrincipal(principal)
                .stream()
                .map(Project::getId)
                .collect(Collectors.toList())), HttpStatus.OK);

    }

    public ResponseEntity<List<VulnBarChartProjection>> getInfraIntfsTop(Principal principal) {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10Interfaces(permissionFactory
                .getProjectForPrincipal(principal)
                .stream()
                .map(Project::getId)
                .collect(Collectors.toList())), HttpStatus.OK);

    }

    public ResponseEntity<List<VulnBarChartProjection>> getWebVulnsTop(Principal principal) {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10WebApps(permissionFactory
                .getProjectForPrincipal(principal)
                .stream()
                .map(Project::getId)
                .collect(Collectors.toList())), HttpStatus.OK);

    }

    public ResponseEntity<List<VulnBarChartProjection>> getWebAppsTop(Principal principal) {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10WebAppVulns(permissionFactory
                .getProjectForPrincipal(principal)
                .stream()
                .map(Project::getId)
                .collect(Collectors.toList())), HttpStatus.OK);
    }

    public ResponseEntity<List<VulnBarChartProjection>> getOpenSourceVulns(Principal principal) {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10OpenSource(permissionFactory
                .getProjectForPrincipal(principal)
                .stream()
                .map(Project::getId)
                .collect(Collectors.toList())), HttpStatus.OK);
    }

    public ResponseEntity<List<VulnBarChartProjection>> getOpenSourceVulnsForCodeProject(Principal principal) {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10OpenSourceCodeProjects(permissionFactory
                .getProjectForPrincipal(principal)
                .stream()
                .map(Project::getId)
                .collect(Collectors.toList())), HttpStatus.OK);
    }

    public ResponseEntity<List<Vulnerability>> getVulnerabilities(Principal principal) {
        return new ResponseEntity<>(vulnTemplate.vulnerabilityRepository.findAll(), HttpStatus.OK);
    }

    public ResponseEntity<List<CisRequirement>> getCisRequirements(Principal principal) {
        return new ResponseEntity<>(vulnTemplate.cisRequirementRepository.findAll(), HttpStatus.OK);
    }

    @Transactional
    public ResponseEntity<Status> setVulnerabilitySeverity(Long id, String severity, Principal principal) {
        Optional<Vulnerability> vulnerability = vulnTemplate.vulnerabilityRepository.findById(id);
        if (!vulnerability.isPresent()){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        if (severity.equals(Constants.VULN_CRITICALITY_HIGH)
                || severity.equals(Constants.VULN_CRITICALITY_CRITICAL)
                || severity.equals(Constants.VULN_CRITICALITY_MEDIUM)
                || severity.equals(Constants.VULN_CRITICALITY_LOW)
                || severity.equals(Constants.INFO_SEVERITY)
                || severity.equals(Constants.SKIP_VULENRABILITY)){
            vulnerability.get().setSeverity(severity);
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @Transactional
    public ResponseEntity<Status> setCisRequirementSeverity(Long id, String severity, Principal principal) {
        Optional<CisRequirement> cisRequirement = vulnTemplate.cisRequirementRepository.findById(id);
        if (!cisRequirement.isPresent()){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        if (severity.equals(Constants.VULN_CRITICALITY_HIGH)
                || severity.equals(Constants.VULN_CRITICALITY_CRITICAL)
                || severity.equals(Constants.VULN_CRITICALITY_MEDIUM)
                || severity.equals(Constants.VULN_CRITICALITY_LOW)
                || severity.equals(Constants.INFO_SEVERITY)
                || severity.equals(Constants.SKIP_VULENRABILITY)){
            cisRequirement.get().setSeverity(severity);
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @Transactional
    public ResponseEntity<List<GlobalStatistic>> getGlobalStatistics(Principal principal) {
        List<Project> projects = findProjectService.findProjectWithoutCodeVulnerabilities();
        List<GlobalStatistic> globalStatistis = new ArrayList<>();
        for (Project project: projects){
            GlobalStatistic globalStatistic = new GlobalStatistic();
            List<ProjectVulnerability> codeVulns = getProjectVulnerabilitiesService
                    .getProjectVulnerabilitiesForProjectAndSourceAndSeverity(project, vulnTemplate.SOURCE_SOURCECODE,  Arrays.asList("Critical", "High"));
            List<ProjectVulnerability> scaVulns = getProjectVulnerabilitiesService
                    .getProjectVulnerabilitiesForProjectAndSourceAndSeverity(project, vulnTemplate.SOURCE_OPENSOURCE,  Arrays.asList("Critical", "High"));
            globalStatistic.setProject(project.getName());
            globalStatistic.setCodeVulns(codeVulns.size());
            globalStatistic.setScaVulns(scaVulns.size());
            globalStatistis.add(globalStatistic);
        }
        return new ResponseEntity<>(globalStatistis, HttpStatus.OK);
    }
}
