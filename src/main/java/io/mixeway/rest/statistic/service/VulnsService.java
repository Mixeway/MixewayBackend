package io.mixeway.rest.statistic.service;

import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.pojo.VulnBarChartProjection;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VulnsService {
    private final VulnTemplate vulnTemplate;
    VulnsService(VulnTemplate vulnTemplate){
        this.vulnTemplate = vulnTemplate;
    }

    public ResponseEntity<List<VulnBarChartProjection>> getCodeVulnsTop() {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10CodeVulns(), HttpStatus.OK);
    }

    public ResponseEntity<List<VulnBarChartProjection>> getCodeProjectsTop() {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10CodeProjects(), HttpStatus.OK);
    }

    public ResponseEntity<List<VulnBarChartProjection>> getInfraVulnsTop() {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10InfraVulns(), HttpStatus.OK);

    }

    public ResponseEntity<List<VulnBarChartProjection>> getInfraIntfsTop() {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10Interfaces(), HttpStatus.OK);

    }

    public ResponseEntity<List<VulnBarChartProjection>> getWebVulnsTop() {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10WebApps(), HttpStatus.OK);

    }

    public ResponseEntity<List<VulnBarChartProjection>> getWebAppsTop() {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10WebAppVulns(), HttpStatus.OK);
    }

    public ResponseEntity<List<VulnBarChartProjection>> getOpenSourceVulns() {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10OpenSource(), HttpStatus.OK);
    }

    public ResponseEntity<List<VulnBarChartProjection>> getOpenSourceVulnsForCodeProject() {
        return new ResponseEntity<>(vulnTemplate.projectVulnerabilityRepository.top10OpenSourceCodeProjects(), HttpStatus.OK);
    }
}
