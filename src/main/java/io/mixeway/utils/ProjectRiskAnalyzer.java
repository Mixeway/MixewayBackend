package io.mixeway.utils;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class ProjectRiskAnalyzer {
    private static final int CODE_CRITIC_WAGE = 10;
    private static final int CODE_HIGH_WAGE = 3;
    private static final int WEBAPP_HIGH_WAGE = 8;
    private static final int WEBAPP_MEDIUM_WAGE = 2;
    private static final int INFRA_HIGH_WAGE = 7;
    private static final int INFRA_MEDIUM_WAGE = 1;
    private static final int OS_CRIT_WAGE = 10;
    private static final int OS_HIGH_WAGE = 6;
    private static final Logger log = LoggerFactory.getLogger(ProjectRiskAnalyzer.class);
    private final InterfaceRepository interfaceRepository;
    private final VulnTemplate vulnTemplate;

    @Autowired
    public ProjectRiskAnalyzer(VulnTemplate vulnTemplate,
                               InterfaceRepository interfaceRepository){
        this.vulnTemplate = vulnTemplate;
        this.interfaceRepository = interfaceRepository;
    }

    public int getProjectCodeRisk(Project project) {
        return vulnTemplate.projectVulnerabilityRepository.countCodeRiskForProject(project.getId(),CODE_CRITIC_WAGE, CODE_HIGH_WAGE);
    }
    public int getProjectInfraRisk(Project project){
        return vulnTemplate.projectVulnerabilityRepository.countNetworkRiskForProject(project.getId(),INFRA_HIGH_WAGE,INFRA_HIGH_WAGE,INFRA_MEDIUM_WAGE);
    }
    public int getProjectWebAppRisk(Project project){
        return vulnTemplate.projectVulnerabilityRepository.countWebAppRiskForProject(project.getId(),WEBAPP_HIGH_WAGE,WEBAPP_HIGH_WAGE,WEBAPP_MEDIUM_WAGE);
    }
    public int getProjectAuditRisk(Project project){
        return 0;
    }

    public int getInterfaceRisk(Interface i) {
        return vulnTemplate.projectVulnerabilityRepository.countRiskForInterface(i.getId(),INFRA_HIGH_WAGE,INFRA_HIGH_WAGE, INFRA_MEDIUM_WAGE);
    }
    public int getWebAppRisk(WebApp webApp){
        return vulnTemplate.projectVulnerabilityRepository.countRiskForWebApp(webApp.getId(),WEBAPP_HIGH_WAGE,WEBAPP_HIGH_WAGE,WEBAPP_MEDIUM_WAGE);
    }
    public int getCodeProjectRisk(CodeProject cp){
        return vulnTemplate.projectVulnerabilityRepository.countRiskForCodeProject(cp.getId(),CODE_CRITIC_WAGE,CODE_HIGH_WAGE,Constants.FORTIFY_NOT_AN_ISSUE);
    }

    public int getCodeProjectOpenSourceRisk(CodeProject codeProject){
        int result = 0;
        result += vulnTemplate.projectVulnerabilityRepository
                .findByCodeProjectAndVulnerabilitySourceAndSeverity(codeProject,
                        vulnTemplate.SOURCE_OPENSOURCE,
                        Constants.VULN_CRITICALITY_CRITICAL).filter(pv -> !pv.getStatus().equals(vulnTemplate.STATUS_REMOVED)).count() * OS_CRIT_WAGE;
        result += vulnTemplate.projectVulnerabilityRepository
                .findByCodeProjectAndVulnerabilitySourceAndSeverity(codeProject,
                        vulnTemplate.SOURCE_OPENSOURCE,
                        Constants.VULN_CRITICALITY_HIGH).filter(pv -> !pv.getStatus().equals(vulnTemplate.STATUS_REMOVED)).count() * OS_HIGH_WAGE;
        return result;
    }
    public int getProjectOpenSourceRisk(Project project) {
        int result = 0;
        result += vulnTemplate.projectVulnerabilityRepository
                .findByProjectAndVulnerabilitySourceAndSeverity(project,
                        vulnTemplate.SOURCE_OPENSOURCE,
                        Constants.VULN_CRITICALITY_CRITICAL).filter(pv -> !pv.getStatus().equals(vulnTemplate.STATUS_REMOVED)).count() * OS_CRIT_WAGE;
        result += vulnTemplate.projectVulnerabilityRepository
                .findByProjectAndVulnerabilitySourceAndSeverity(project,
                        vulnTemplate.SOURCE_OPENSOURCE,
                        Constants.VULN_CRITICALITY_HIGH).filter(pv -> !pv.getStatus().equals(vulnTemplate.STATUS_REMOVED)).count() * OS_HIGH_WAGE;
        return result;
    }
}
