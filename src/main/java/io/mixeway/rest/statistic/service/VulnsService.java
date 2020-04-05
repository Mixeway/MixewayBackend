package io.mixeway.rest.statistic.service;

import io.mixeway.db.repository.SoftwarePacketVulnerabilityRepository;
import io.mixeway.pojo.BarChartProjection2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.repository.CodeVulnRepository;
import io.mixeway.db.repository.InfrastructureVulnRepository;
import io.mixeway.db.repository.WebAppVulnRepository;

import java.util.List;

@Service
public class VulnsService {
    private final CodeVulnRepository codeVulnRepository;
    private final InfrastructureVulnRepository infrastructureVulnRepository;
    private final WebAppVulnRepository webAppVulnRepository;
    private final SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;

    VulnsService(CodeVulnRepository codeVulnRepository, InfrastructureVulnRepository infrastructureVulnRepository,
                 WebAppVulnRepository webAppVulnRepository, SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository){
        this.codeVulnRepository = codeVulnRepository;
        this.infrastructureVulnRepository = infrastructureVulnRepository;
        this.webAppVulnRepository = webAppVulnRepository;
        this.softwarePacketVulnerabilityRepository = softwarePacketVulnerabilityRepository;
    }

    public ResponseEntity<List<BarChartProjection2>> getCodeVulnsTop() {
        return new ResponseEntity<>(codeVulnRepository.get10TenCodeVulns(), HttpStatus.OK);
    }

    public ResponseEntity<List<BarChartProjection2>> getCodeProjectsTop() {
        return new ResponseEntity<>(codeVulnRepository.get10TopCodeProjects(), HttpStatus.OK);
    }

    public ResponseEntity<List<BarChartProjection2>> getInfraVulnsTop() {
        return new ResponseEntity<>(infrastructureVulnRepository.getTopVulns(), HttpStatus.OK);

    }

    public ResponseEntity<List<BarChartProjection2>> getInfraIntfsTop() {
        return new ResponseEntity<>(infrastructureVulnRepository.getTopTargets(), HttpStatus.OK);

    }

    public ResponseEntity<List<BarChartProjection2>> getWebVulnsTop() {
        return new ResponseEntity<>(webAppVulnRepository.getTopVulns(), HttpStatus.OK);

    }

    public ResponseEntity<List<BarChartProjection2>> getWebAppsTop() {
        return new ResponseEntity<>(webAppVulnRepository.getTopTargets(), HttpStatus.OK);
    }

    public ResponseEntity<List<BarChartProjection2>> getOpenSourceVulns() {
        return new ResponseEntity<>(softwarePacketVulnerabilityRepository.getTopOpenSourceVulns(), HttpStatus.OK);
    }

    public ResponseEntity<List<BarChartProjection2>> getOpenSourceVulnsForCodeProject() {
        return new ResponseEntity<>(softwarePacketVulnerabilityRepository.getTopOpenSourceVulnsForCodeProject(), HttpStatus.OK);
    }
}
