package io.mixeway.rest.utils;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.CodeVulnRepository;
import io.mixeway.db.repository.InfrastructureVulnRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.WebAppVulnRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import io.mixeway.config.Constants;

@Component
public class ProjectRiskAnalyzer {
    private static final int CODE_CRITIC_WAGE = 10;
    private static final int CODE_HIGH_WAGE = 3;
    private static final int WEBAPP_HIGH_WAGE = 8;
    private static final int WEBAPP_MEDIUM_WAGE = 2;
    private static final int INFRA_HIGH_WAGE = 7;
    private static final int INFRA_MEDIUM_WAGE = 1;
    private static final Logger log = LoggerFactory.getLogger(ProjectRiskAnalyzer.class);
    private final CodeVulnRepository codeVulnRepository;
    private final InfrastructureVulnRepository infrastructureVulnRepository;
    private final WebAppVulnRepository webAppVulnRepository;
    private final InterfaceRepository interfaceRepository;

    @Autowired
    public ProjectRiskAnalyzer (CodeVulnRepository codeVulnRepository,
                         InfrastructureVulnRepository infrastructureVulnRepository,
                         WebAppVulnRepository webAppVulnRepository,
                         InterfaceRepository interfaceRepository){
        this.infrastructureVulnRepository = infrastructureVulnRepository;
        this.codeVulnRepository = codeVulnRepository;
        this.webAppVulnRepository = webAppVulnRepository;
        this.interfaceRepository = interfaceRepository;
    }

    public int getProjectCodeRisk(Project project) {
        int result = 0;
        if (project.getCodes() != null){
            try {
                result += codeVulnRepository.getCountByProjectIdSeverityAndAnalysis(project.getId(),Constants.VULN_CRITICALITY_CRITICAL, Constants.FORTIFY_ANALYSIS_EXPLOITABLE) * CODE_CRITIC_WAGE;
                result += codeVulnRepository.getCountByProjectIdSeverityAndAnalysis(project.getId(),Constants.VULN_CRITICALITY_HIGH, Constants.FORTIFY_ANALYSIS_EXPLOITABLE) * CODE_HIGH_WAGE;
            } catch (NullPointerException ex){
                log.warn("Something wrong with code for data: {}",project.getName());
            }
        }
        return result;
    }
    public int getProjectInfraRisk(Project project){
        int result = 0;
        if (project.getAssets() != null) {
            result+=infrastructureVulnRepository.getCountByProjectIdAndThreat(project.getId(),Constants.VULN_CRITICALITY_CRITICAL) * INFRA_HIGH_WAGE;
            result+=infrastructureVulnRepository.getCountByProjectIdAndThreat(project.getId(),Constants.VULN_CRITICALITY_HIGH) * INFRA_HIGH_WAGE;
            result+=infrastructureVulnRepository.getCountByProjectIdAndThreat(project.getId(),Constants.IF_VULN_THREAT_MEDIUM) * INFRA_MEDIUM_WAGE;
        }
        return result;
    }
    public int getProjectWebAppRisk(Project project){
        int result = 0;
        if (project.getWebapps() != null) {
            result += webAppVulnRepository.getCountByProjectIdAndSeverity(project.getId(), Constants.VULN_CRITICALITY_HIGH) * WEBAPP_HIGH_WAGE;
            result += webAppVulnRepository.getCountByProjectIdAndSeverity(project.getId(), Constants.IF_VULN_THREAT_MEDIUM) * WEBAPP_MEDIUM_WAGE;
        }
        return result;
    }
    public int getProjectAuditRisk(Project project){
        return 0;
    }

    public int getInterfaceRisk(Interface i) {
        int result = 0;
        result+=infrastructureVulnRepository.getCountByInterfaceIdAndThreat(i.getId(),Constants.VULN_CRITICALITY_CRITICAL) * INFRA_HIGH_WAGE;
        result+=infrastructureVulnRepository.getCountByInterfaceIdAndThreat(i.getId(),Constants.VULN_CRITICALITY_HIGH) * INFRA_HIGH_WAGE;
        result+=infrastructureVulnRepository.getCountByInterfaceIdAndThreat(i.getId(),Constants.IF_VULN_THREAT_MEDIUM) * INFRA_MEDIUM_WAGE;
        return result;
    }
    public int getWebAppRisk(WebApp webApp){
        int result = 0;
        result += webAppVulnRepository.getCountByWebAppIdAndSeverity(webApp.getId(), Constants.VULN_CRITICALITY_HIGH) * WEBAPP_HIGH_WAGE;
        result += webAppVulnRepository.getCountByWebAppIdAndSeverity(webApp.getId(), Constants.IF_VULN_THREAT_MEDIUM) * WEBAPP_MEDIUM_WAGE;
        return result;
    }
    public int getCodeProjectRisk(CodeProject cp){
        int result = 0;
        result += codeVulnRepository.getCountByCodeProjectIdSeverityAndAnalysis(cp.getId(),Constants.VULN_CRITICALITY_CRITICAL, Constants.FORTIFY_ANALYSIS_EXPLOITABLE) * CODE_CRITIC_WAGE;
        result += codeVulnRepository.getCountByCodeProjectIdSeverityAndAnalysis(cp.getId(),Constants.VULN_CRITICALITY_HIGH, Constants.FORTIFY_ANALYSIS_EXPLOITABLE) * CODE_HIGH_WAGE;
        return result;
    }
}
