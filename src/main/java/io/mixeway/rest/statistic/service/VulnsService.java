package io.mixeway.rest.statistic.service;

import io.mixeway.db.entity.Project;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.pojo.VulnBarChartProjection;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.List;
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
}
