package io.mixeway.domain.service.vulnhistory;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.VulnHistory;
import io.mixeway.db.repository.NodeAuditRepository;
import io.mixeway.db.repository.VulnHistoryRepository;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class CreateVulnHistoryService {
    private final VulnHistoryRepository vulnHistoryRepository;
    private final VulnTemplate vulnTemplate;
    private final NodeAuditRepository nodeAuditRepository;

    private List<String> severities = new ArrayList<String>(){{
        add("Medium" );
        add("High");
        add("Critical");
    }};
    private List<String> scores = new ArrayList<String>(){{
        add("WARN" );
        add("FAIL");
    }};
    private List<String> critSeverities = new ArrayList<String>(){{
        add("High");
        add("Critical");
    }};

    private DateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public void createScheduled(Project project){
        VulnHistory vulnHistory = new VulnHistory();
        vulnHistory.setName(Constants.VULN_HISTORY_ALL);
        vulnHistory.setInfrastructureVulnHistory(createInfraVulnHistory(project));
        vulnHistory.setWebAppVulnHistory(createWebAppVulnHistory(project));
        vulnHistory.setCodeVulnHistory(createCodeVulnHistory(project));
        vulnHistory.setAuditVulnHistory(createAuditHistory(project));
        vulnHistory.setSoftwarePacketVulnNumber((long) createSoftwarePacketHistory(project));
        vulnHistory.setProject(project);
        vulnHistory.setInserted(format.format(new Date()));
        vulnHistoryRepository.save(vulnHistory);
    }
    public void create(Project project, String date, Long infra, Long webApp, Long code, Long audit, Long software){
        VulnHistory vulnHistory = new VulnHistory();
        vulnHistory.setName(Constants.VULN_HISTORY_ALL);
        vulnHistory.setInfrastructureVulnHistory(infra);
        vulnHistory.setWebAppVulnHistory(webApp);
        vulnHistory.setCodeVulnHistory(code);
        vulnHistory.setAuditVulnHistory(audit);
        vulnHistory.setSoftwarePacketVulnNumber(software);
        vulnHistory.setProject(project);
        vulnHistory.setInserted(date);
        vulnHistoryRepository.save(vulnHistory);
    }
    private Long createWebAppVulnHistory(Project p){
        return vulnTemplate.projectVulnerabilityRepository
                .findByWebAppInAndVulnerabilitySourceAndSeverityIn(new ArrayList<>(p.getWebapps()),vulnTemplate.SOURCE_WEBAPP, severities).count();

    }

    private Long createCodeVulnHistory(Project p){
        return vulnTemplate.projectVulnerabilityRepository.findByProjectAndVulnerabilitySourceAndAnalysisNot(p,vulnTemplate.SOURCE_SOURCECODE, Constants.FORTIFY_NOT_AN_ISSUE).count();
    }
    private Long createInfraVulnHistory(Project p){
        return getInfraVulnsForProject(p);
    }
    private Long createAuditHistory(Project p){
        return (long)(nodeAuditRepository.findByNodeInAndScoreIn(p.getNodes(),scores).size());
    }
    private int createSoftwarePacketHistory(Project project) {

        return vulnTemplate.projectVulnerabilityRepository.findByProjectAndVulnerabilitySourceAndSeverityIn(project,vulnTemplate.SOURCE_OPENSOURCE, critSeverities).size();
    }
    private long getInfraVulnsForProject(Project project){
        return vulnTemplate.projectVulnerabilityRepository.findByProjectAndVulnerabilitySourceAndSeverityIn(project, vulnTemplate.SOURCE_NETWORK, severities).size();
    }
}
