package io.mixeway.rest.statistic.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CisRequirement;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Vulnerability;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.pojo.Status;
import io.mixeway.pojo.VulnBarChartProjection;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class VulnsService {
    private final VulnTemplate vulnTemplate;
    private final PermissionFactory permissionFactory;
    VulnsService(VulnTemplate vulnTemplate, PermissionFactory permissionFactory){
        this.vulnTemplate = vulnTemplate;
        this.permissionFactory = permissionFactory;
    }

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
}
