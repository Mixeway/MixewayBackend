package io.mixeway.rest.project.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.rest.project.model.ContactList;
import io.mixeway.rest.project.model.ProjectVulnTrendChart;
import io.mixeway.rest.project.model.ProjectVulnTrendChartSerie;
import io.mixeway.rest.project.model.RiskCards;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import springfox.documentation.service.Contact;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import java.security.Principal;
import java.util.*;

@Service
public class ProjectRestService {
    private static final Logger log = LoggerFactory.getLogger(ProjectRestService.class);

    private final RoutingDomainRepository routingDomainRepository;
    private final ProxiesRepository proxiesRepository;
    private final ProjectRepository projectRepository;
    private final InterfaceRepository interfaceRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final CodeProjectRepository codeProjectRepository;
    private final VulnHistoryRepository vulnHistoryRepository;
    private final PermissionFactory permissionFactory;
    private final InfrastructureVulnRepository infrastructureVulnRepository;
    private final CodeVulnRepository codeVulnRepository;
    private final WebAppVulnRepository webAppVulnRepository;
    private final SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;
    private final SoftwarePacketRepository softwarePacketRepository;
    private final ScannerRepository scannerRepository;

    @Autowired
    ProjectRestService(RoutingDomainRepository routingDomainRepository,
                        ProxiesRepository proxiesRepository,
                        ProjectRepository projectRepository,
                        InterfaceRepository interfaceRepository,
                        ProjectRiskAnalyzer projectRiskAnalyzer,
                        CodeProjectRepository codeProjectRepository,
                        VulnHistoryRepository vulnHistoryRepository,
                        InfrastructureVulnRepository infrastructureVulnRepository,
                        CodeVulnRepository codeVulnRepository,
                        WebAppVulnRepository webAppVulnRepository,
                        SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository,
                        ScannerRepository scannerRepository,
                       PermissionFactory permissionFactory,
                       SoftwarePacketRepository softwarePacketRepository){
        this.routingDomainRepository = routingDomainRepository;
        this.proxiesRepository = proxiesRepository;
        this.projectRepository = projectRepository;
        this.interfaceRepository = interfaceRepository;
        this.projectRiskAnalyzer = projectRiskAnalyzer;
        this.softwarePacketRepository = softwarePacketRepository;
        this.permissionFactory = permissionFactory;
        this.codeProjectRepository = codeProjectRepository;
        this.vulnHistoryRepository = vulnHistoryRepository;
        this.infrastructureVulnRepository = infrastructureVulnRepository;
        this.codeVulnRepository = codeVulnRepository;
        this.webAppVulnRepository = webAppVulnRepository;
        this.scannerRepository = scannerRepository;
        this.softwarePacketVulnerabilityRepository = softwarePacketVulnerabilityRepository;
    }


    private ArrayList<String> severityList = new ArrayList<String>() {{
        add(Constants.API_SEVERITY_CRITICAL);
        add(Constants.API_SEVERITY_HIGH);
        add(Constants.API_SEVERITY_MEDIUM);
        add(Constants.API_SEVERITY_LOW);
    }};


    public ResponseEntity<RiskCards> showProjectRisk(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if ( project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            int webAppRisk = projectRiskAnalyzer.getProjectWebAppRisk(project.get());
            int assetRisk = projectRiskAnalyzer.getProjectInfraRisk(project.get());
            int codeRisk = projectRiskAnalyzer.getProjectCodeRisk(project.get());
            int auditRisk = projectRiskAnalyzer.getProjectAuditRisk(project.get());
            int openSourceRisk = projectRiskAnalyzer.getProjectOpenSourceRisk(project.get());
            int codeProjects = codeProjectRepository.findByCodeGroupIn(project.get().getCodes()).size();
            RiskCards riskCards = new RiskCards();
            riskCards.setWebAppNumber(project.get().getWebapps().size());
            riskCards.setWebAppRisk(webAppRisk > 100 ? 100 : webAppRisk);
            riskCards.setAudit(project.get().getNodes().size());
            riskCards.setAuditRisk(auditRisk > 100 ? 100 : auditRisk);
            riskCards.setAssetNumber(interfaceRepository.findByAssetIn(new ArrayList<>(project.get().getAssets())).size());
            riskCards.setAssetRisk(assetRisk > 100 ? 100 : assetRisk);
            riskCards.setCodeRepoNumber(codeProjects == 0 ? project.get().getCodes().size() : codeProjects);
            riskCards.setCodeRisk(codeRisk > 100 ? 100 : codeRisk);
            riskCards.setOpenSourceLibs(softwarePacketRepository.getSoftwarePacketForProject(project.get().getId()).size());
            riskCards.setOpenSourceRisk(openSourceRisk > 100 ? 100 : openSourceRisk);
            riskCards.setProjectName(project.get().getName());
            riskCards.setProjectDescription(project.get().getDescription());
            return new ResponseEntity<>(riskCards,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }



    public ResponseEntity<List<RoutingDomain>> showRoutingDomains() {
        return new ResponseEntity<>(routingDomainRepository.findAll(),HttpStatus.OK);
    }

    public ResponseEntity<List<Proxies>> showProxies() {
        return new ResponseEntity<>(proxiesRepository.findAll(), HttpStatus.OK);
    }



    public ResponseEntity<ProjectVulnTrendChart> showVulnTrendChart(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id) ;
        LinkedList<Integer> infraVulnTrend = new LinkedList<>();
        LinkedList<Integer> webAppVulnTrend = new LinkedList<>();
        LinkedList<Integer> codeVulnTrend = new LinkedList<>();
        LinkedList<Integer> auditVulnTrend = new LinkedList<>();
        LinkedList<Integer> softwareVulnTrend = new LinkedList<>();
        LinkedList<String> dates = new LinkedList<>();
        List<ProjectVulnTrendChartSerie>series = new ArrayList<>();
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            List<VulnHistory> vulnHistories = vulnHistoryRepository.getLastTwoVulnForProject(project.get().getId()) ;
            for(VulnHistory vulnHistory : vulnHistories){
                infraVulnTrend.add(vulnHistory.getInfrastructureVulnHistory().intValue());
                webAppVulnTrend.add(vulnHistory.getWebAppVulnHistory().intValue());
                codeVulnTrend.add(vulnHistory.getCodeVulnHistory().intValue());
                auditVulnTrend.add(vulnHistory.getAuditVulnHistory().intValue());
                softwareVulnTrend.add(vulnHistory.getSoftwarePacketVulnNumber().intValue());
                dates.add(vulnHistory.getInserted().split(" ")[0]);
            }
            if (infraVulnTrend.stream().mapToInt(i-> i).sum() >0){
                ProjectVulnTrendChartSerie infraSerie = new ProjectVulnTrendChartSerie();
                infraSerie.setName(Constants.INFRA_VULN_TREND_LABEL);
                infraSerie.setValues(infraVulnTrend);
                series.add(infraSerie);
            }
            if (webAppVulnTrend.stream().mapToInt(i-> i).sum() >0){
                ProjectVulnTrendChartSerie webAPpSerie = new ProjectVulnTrendChartSerie();
                webAPpSerie.setName(Constants.WEBAPP_VULN_TREND_LABEL);
                webAPpSerie.setValues(webAppVulnTrend);
                series.add(webAPpSerie);
            }
            if (codeVulnTrend.stream().mapToInt(i-> i).sum() >0){
                ProjectVulnTrendChartSerie codeSerie = new ProjectVulnTrendChartSerie();
                codeSerie.setName(Constants.CODE_VULN_TREND_LABEL);
                codeSerie.setValues(codeVulnTrend);
                series.add(codeSerie);
            }
            if (auditVulnTrend.stream().mapToInt(i-> i).sum() >0){
                ProjectVulnTrendChartSerie auditSerie = new ProjectVulnTrendChartSerie();
                auditSerie.setName(Constants.AUDIT_VULN_TREND_LABEL);
                auditSerie.setValues(auditVulnTrend);
                series.add(auditSerie);
            }
            if (softwareVulnTrend.stream().mapToInt(i -> i).sum() > 0){
                ProjectVulnTrendChartSerie softSerie = new ProjectVulnTrendChartSerie();
                softSerie.setName(Constants.SOFT_VULN_TREND_LABEL);
                softSerie.setValues(softwareVulnTrend);
                series.add(softSerie);
            }
            ProjectVulnTrendChart projectVulnTrendChart = new ProjectVulnTrendChart();
            projectVulnTrendChart.setDates(dates);
            projectVulnTrendChart.setSeries(series);
            return new ResponseEntity<>(projectVulnTrendChart,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<HashMap<String,Long>> showSeverityChart(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        HashMap<String,Long> pieData = new HashMap<>();
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            for (String severity : severityList){
                pieData.put(severity,
                        (infrastructureVulnRepository.countByIntfInAndSeverity(interfaceRepository.findByAssetIn(new ArrayList<>(project.get().getAssets())),severity)
                        + codeVulnRepository.countByCodeProjectInAndSeverityAndAnalysis(codeProjectRepository.findByCodeGroupIn(project.get().getCodes()),severity,Constants.FORTIFY_ANALYSIS_EXPLOITABLE)
                        + webAppVulnRepository.countByWebAppInAndSeverity(project.get().getWebapps(),severity)
                        + softwarePacketVulnerabilityRepository.getSoftwareVulnsForProjectAndSeverity(project.get().getId(), severity).size()));
            }
            return new ResponseEntity<>(pieData,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> updateContactList(Long id, ContactList contactList) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && verifyContactList(contactList) ){
            project.get().setContactList(contactList.getContactList());
            projectRepository.save(project.get());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    private boolean verifyContactList(ContactList contactList) {
        boolean result = true;
        try {
            for (String email : contactList.getContactList().split(",")) {
                InternetAddress emailAddr = new InternetAddress(email);
                emailAddr.validate();
            }
        } catch (AddressException ex) {
            result = false;
        }
        return result;
    }

    public ResponseEntity<List<ScannerType>> scannersAvaliable() {
        return new ResponseEntity<>(scannerRepository.getDistinctScannerTypes(), HttpStatus.OK);
    }
}
