/*
 * @created  2020-08-27 : 14:44
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.utils;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.SecurityGateway;
import io.mixeway.db.repository.SecurityGatewayRepository;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SecurityQualityGateway {
    private final SecurityGatewayRepository securityGatewayRepository;
    private final VulnTemplate vulnTemplate;

    public SecurityQualityGateway(SecurityGatewayRepository securityGatewayRepository, VulnTemplate vulnTemplate){
        this.securityGatewayRepository = securityGatewayRepository;
        this.vulnTemplate = vulnTemplate;
    }

    /**
     * Return results for gateway for CICD /Scanner
     */
    //TODO WEB & IMAGE
    public SecurityGatewayEntry buildGatewayResponse(List<ProjectVulnerability> projectVulnerabilities){
        SecurityGateway securityGateway = securityGatewayRepository.findAll().stream().findFirst().orElse(null);

        SecurityGatewayEntry securityGatewayEntry = null;
        if (securityGateway.isGrade()){
            securityGatewayEntry = SecurityGatewayEntry.builder()
                    .sastCritical((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_SOURCECODE.getId()) && isCritical(v) && v.getGrade() == 1).count())
                    .sastHigh((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_SOURCECODE.getId()) && isHigh(v) && v.getGrade() == 1).count())
                    .sastMedium((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_SOURCECODE.getId()) && isMedium(v) && v.getGrade() == 1).count())
                    .sastLow((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_SOURCECODE.getId()) && isLow(v) && v.getGrade() == 1).count())
                    .osCritical((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_OPENSOURCE.getId()) && isCritical(v) && v.getGrade() == 1).count())
                    .osHigh((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_OPENSOURCE.getId()) && isHigh(v) && v.getGrade() == 1).count())
                    .osMedium((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_OPENSOURCE.getId()) && isMedium(v) && v.getGrade() == 1).count())
                    .osLow((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_OPENSOURCE.getId()) && isLow(v) && v.getGrade() == 1).count())
                    .build();
            int vulnGraded = securityGatewayEntry.getImageHigh() +
                    securityGatewayEntry.getSastCritical() +
                    securityGatewayEntry.getSastHigh() +
                    securityGatewayEntry.getOsCritical() +
                    securityGatewayEntry.getOsHigh();
            securityGatewayEntry.setPassed(vulnGraded < securityGateway.getVuln());
        } else {
            securityGatewayEntry = SecurityGatewayEntry.builder()
                    .sastCritical((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_SOURCECODE.getId()) && isCritical(v) && (v.getGrade() == 1 || v.getGrade() == -1)).count())
                    .sastHigh((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_SOURCECODE.getId()) && isHigh(v) && (v.getGrade() == 1 || v.getGrade() == -1)).count())
                    .sastMedium((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_SOURCECODE.getId()) && isMedium(v) && (v.getGrade() == 1 || v.getGrade() == -1)).count())
                    .sastLow((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_SOURCECODE.getId()) && isLow(v) && (v.getGrade() == 1 || v.getGrade() == -1)).count())
                    .osCritical((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_OPENSOURCE.getId()) && isCritical(v) && (v.getGrade() == 1 || v.getGrade() == -1)).count())
                    .osHigh((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_OPENSOURCE.getId()) && isHigh(v) && (v.getGrade() == 1 || v.getGrade() == -1)).count())
                    .osMedium((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_OPENSOURCE.getId()) && isMedium(v) && (v.getGrade() == 1 || v.getGrade() == -1)).count())
                    .osLow((int)projectVulnerabilities.stream().filter(v -> v.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_OPENSOURCE.getId()) && isLow(v) && (v.getGrade() == 1 || v.getGrade() == -1)).count())
                    .build();
            boolean passedHigh = (securityGatewayEntry.getSastHigh() + securityGatewayEntry.getOsHigh()) <= securityGateway.getHigh();
            boolean passwedMedium = (securityGatewayEntry.getSastMedium() + securityGatewayEntry.getOsMedium()) <= securityGateway.getMedium();
            boolean passwedCritical = (securityGatewayEntry.getSastCritical() + securityGatewayEntry.getOsCritical()) <= securityGateway.getCritical();
            securityGatewayEntry.setPassed(passedHigh && passwedCritical && passwedMedium);
        }
        return securityGatewayEntry;
    }

    private boolean isCritical(ProjectVulnerability v) {
        return v.getSeverity().toLowerCase().equals(Constants.API_SEVERITY_CRITICAL.toLowerCase());
    }
    private boolean isHigh(ProjectVulnerability v) {
        return v.getSeverity().toLowerCase().equals(Constants.API_SEVERITY_HIGH.toLowerCase());
    }
    private boolean isMedium(ProjectVulnerability v) {
        return v.getSeverity().toLowerCase().equals(Constants.API_SEVERITY_MEDIUM.toLowerCase()) ;
    }
    private boolean isLow(ProjectVulnerability v) {
        return v.getSeverity().toLowerCase().equals(Constants.API_SEVERITY_LOW.toLowerCase());
    }


}
