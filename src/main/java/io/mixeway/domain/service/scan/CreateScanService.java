package io.mixeway.domain.service.scan;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CodeProjectBranchRepository;
import io.mixeway.db.repository.ScanRepository;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class CreateScanService {
    private final ScanRepository scanRepository;
    private final VulnTemplate vulnTemplate;
    private final CodeProjectBranchRepository codeProjectBranchRepository;
    private final FindScanService findScanService;

    private static final Predicate<ProjectVulnerability> IS_HIGH_OR_CRITICAL =
            pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL) || pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH);
    private static final Predicate<ProjectVulnerability> IS_MEDIUM =
            pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM);
    private static final Predicate<ProjectVulnerability> IS_LOW =
            pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW);

    private static final Predicate<ProjectVulnerability> IS_NOT_REMOVED_AND_HAS_GRADE =
            pv -> !Objects.equals(pv.getStatus().getName(), Constants.STATUS_REMOVED) && pv.getGrade() != 0;

    public Scan createCodeScan(CodeProject codeProject, String branch, String commitId, String type, Principal principal) {
        Scan scan = Optional.ofNullable(findScanService.findScan(commitId, codeProject))
                .orElseGet(() -> new Scan(principal.getName(), codeProject, branch, commitId, type));

        CodeProjectBranch codeProjectBranch = codeProjectBranchRepository.findByCodeProjectAndName(codeProject, branch);
        List<ProjectVulnerability> projectVulnerabilities =
                vulnTemplate.projectVulnerabilityRepository
                        .findByCodeProjectAndCodeProjectBranch(codeProject, codeProjectBranch)
                        .stream()
                        .filter(IS_NOT_REMOVED_AND_HAS_GRADE)
                        .collect(Collectors.toList());
        switch (type) {
            case Constants.IAC_LABEL:
                projectVulnerabilities = projectVulnerabilities.stream().filter(pv -> Objects.equals(pv.getVulnerabilitySource().getId(), vulnTemplate.SOURCE_IAC.getId())).collect(Collectors.toList());
                break;
            case Constants.SECRET_LABEL:
                projectVulnerabilities = projectVulnerabilities.stream().filter(pv -> Objects.equals(pv.getVulnerabilitySource().getId(), vulnTemplate.SOURCE_GITLEAKS.getId())).collect(Collectors.toList());
                break;
            case Constants.SAST_LABEL:
                projectVulnerabilities = projectVulnerabilities.stream().filter(pv -> Objects.equals(pv.getVulnerabilitySource().getId(), vulnTemplate.SOURCE_SOURCECODE.getId())).collect(Collectors.toList());
                break;
            case Constants.SCA_LABEL:
                projectVulnerabilities = projectVulnerabilities.stream().filter(pv -> Objects.equals(pv.getVulnerabilitySource().getId(), vulnTemplate.SOURCE_OPENSOURCE.getId())).collect(Collectors.toList());
                break;
        }
        scan.setVulnCrit((int) projectVulnerabilities.stream().filter(IS_HIGH_OR_CRITICAL).count());
        scan.setVulnMedium((int) projectVulnerabilities.stream().filter(IS_MEDIUM).count());
        scan.setVulnLow((int) projectVulnerabilities.stream().filter(IS_LOW).count());
        return scanRepository.save(scan);
    }

    public void createWebAppScan(WebApp webApp, String branch, String commitId, Principal principal) {
        Scan scan = new Scan(principal.getName(), webApp, branch, commitId);
        List<ProjectVulnerability> projectVulnerabilities =
                vulnTemplate.projectVulnerabilityRepository
                        .findByWebApp(webApp)
                        .stream()
                        .filter(IS_NOT_REMOVED_AND_HAS_GRADE)
                        .collect(Collectors.toList());
        scan.setVulnCrit((int) projectVulnerabilities.stream().filter(IS_HIGH_OR_CRITICAL).count());
        scan.setVulnMedium((int) projectVulnerabilities.stream().filter(IS_MEDIUM).count());
        scan.setVulnLow((int) projectVulnerabilities.stream().filter(IS_LOW).count());
        scanRepository.save(scan);
    }

    public void createNetworkScan(Interface anInterface, String branch, String commitId, Principal principal) {
        Scan scan = new Scan(principal.getName(), anInterface, branch, commitId);
        List<ProjectVulnerability> projectVulnerabilities =
                vulnTemplate.projectVulnerabilityRepository
                        .findByAnInterface(anInterface)
                        .stream()
                        .filter(IS_NOT_REMOVED_AND_HAS_GRADE)
                        .collect(Collectors.toList());
        scan.setVulnCrit((int) projectVulnerabilities.stream().filter(IS_HIGH_OR_CRITICAL).count());
        scan.setVulnMedium((int) projectVulnerabilities.stream().filter(IS_MEDIUM).count());
        scan.setVulnLow((int) projectVulnerabilities.stream().filter(IS_LOW).count());
        scanRepository.save(scan);
    }


}