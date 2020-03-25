package io.mixeway.scheduler;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.opensourcescan.dependencytrack.apiclient.DependencyTrackApiClient;
import io.mixeway.plugins.remotefirewall.apiclient.RfwApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import io.mixeway.config.Constants;
import io.mixeway.plugins.remotefirewall.model.Rule;
import io.mixeway.pojo.DOPMailTemplateBuilder;
import io.mixeway.pojo.EmailVulnHelper;
import io.mixeway.pojo.ScanHelper;
import org.springframework.transaction.annotation.Transactional;

import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.DateFormat;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
@Transactional
public class CronScheduler {
    private final SettingsRepository settingsRepository;
    private final VulnHistoryRepository vulnHistoryRepository;
    private final ProjectRepository projectRepository;
    private final WebAppVulnRepository webAppVulnRepository;
    private final CodeVulnRepository codeVulnRepository;
    private final NodeAuditRepository nodeAuditRepository;
    private final InfrastructureVulnRepository infrastructureVulnRepository;
    private final InterfaceRepository interfaceRepository;
    private final NessusScanRepository nessusScanRepository;
    private final JavaMailSender sender;
    private final CodeProjectRepository codeProjectRepository;
    private final SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;
    private final RfwApiClient rfwApiClient;
    private final ScanHelper scanHelper;
    private final DependencyTrackApiClient dependencyTrackApiClient;
    @Autowired
    public CronScheduler(SettingsRepository settingsRepository, VulnHistoryRepository vulnHistoryRepository,
            ProjectRepository projectRepository, WebAppVulnRepository webAppVulnRepository, DependencyTrackApiClient dependencyTrackApiClient,
            CodeVulnRepository codeVulnRepository,  NodeAuditRepository nodeAuditRepository, InfrastructureVulnRepository infrastructureVulnRepository,
            InterfaceRepository interfaceRepository, NessusScanRepository nessusScanRepository, JavaMailSender sender,
            SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository,RfwApiClient rfwApiClient,
            ScanHelper scanHelper, CodeProjectRepository codeProjectRepository) {
        this.settingsRepository = settingsRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.projectRepository = projectRepository;
        this.vulnHistoryRepository = vulnHistoryRepository;
        this.webAppVulnRepository = webAppVulnRepository;
        this.codeVulnRepository = codeVulnRepository;
        this.dependencyTrackApiClient = dependencyTrackApiClient;
        this.nodeAuditRepository = nodeAuditRepository;
        this.infrastructureVulnRepository = infrastructureVulnRepository;
        this.nessusScanRepository = nessusScanRepository;
        this.interfaceRepository = interfaceRepository;
        this.softwarePacketVulnerabilityRepository = softwarePacketVulnerabilityRepository;
        this.rfwApiClient =rfwApiClient;
        this.sender = sender;
        this.scanHelper = scanHelper;
    }

    private DOPMailTemplateBuilder templateBuilder = new DOPMailTemplateBuilder();
    private List<String> severities = new ArrayList<String>(){{
        add("Medium" );
        add("High");
        add("Critical");
    }};
    private List<String> scores = new ArrayList<String>(){{
        add("WARN" );
        add("FAIL");
    }};


    private DateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final Logger log = LoggerFactory.getLogger(CronScheduler.class);

    // Every 12h
    @Scheduled(cron="0 0 12 * * *" )
    public void createHistoryForVulns() {
        for(Project project : projectRepository.findAll()){
            VulnHistory vulnHistory = new VulnHistory();
            vulnHistory.setName(Constants.VULN_HISTORY_ALL);
            vulnHistory.setInfrastructureVulnHistory(createInfraVulnHistory(project));
            vulnHistory.setWebAppVulnHistory(createWebAppVulnHistory(project));
            vulnHistory.setCodeVulnHistory(createCodeVulnHistory(project));
            vulnHistory.setAuditVulnHistory(createAuditHistory(project));
            vulnHistory.setSoftwarePacketVulnNumber(createSoftwarePacketHistory(project));
            vulnHistory.setProject(project);
            vulnHistory.setInserted(format.format(new Date()));
            vulnHistoryRepository.save(vulnHistory);
        }
        log.info("History records for defined projects completed successfully.") ;

    }

    private Long createSoftwarePacketHistory(Project project) {

        return (Long) (long)softwarePacketVulnerabilityRepository.getSoftwareVulnsForProject(project.getId()).size();
    }
    @Scheduled(initialDelay=0,fixedDelay = 1500000)
    public void getDepTrackVulns() {
        try {
            for (CodeProject cp : codeProjectRepository.getCodeProjectsWithOSIntegrationEnabled()){
                dependencyTrackApiClient.loadVulnerabilities(cp);
            }
            log.info("Successfully synchronized with OpenSource scanner");
        } catch (Exception ignored) {
        }

    }

    //every 3 minutes
    //@Scheduled(initialDelay=0,fixedDelay = 150000)
    public void verifyRFWRules() throws  KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        try {
            for (NessusScan ns : nessusScanRepository.getRunningScansWithRfwConfigured()) {
                List<Rule> rules = rfwApiClient.getListOfRules(ns.getNessus()).stream().filter(r -> r.getChain().equals("INPUT")).collect(Collectors.toList());
                List<String> runningScansIps = scanHelper.prepareTargetsForScan(ns, false);
                for (Rule r : rules) {
                    if (!runningScansIps.contains(r.getDestination()))
                        log.error("Security Violation! RFW Contains rule which is not valid in scope of running tests !! - {}", r.getDestination());
                }
            }
        } catch (NullPointerException ignored) {}

    }

    @Scheduled(cron = "#{@getTrendEmailExpression}")
    public void sendTrendEmails(){

            List<String> emailsToSend = projectRepository.getUniqueContactListEmails();
            for (String email : emailsToSend) {
                try {
                    List<List<EmailVulnHelper>> vulns = new ArrayList<>();
                    List<Project> projectForEmail = projectRepository.getUniqueContactListEmails(email);
                    for (Project project : projectForEmail) {
                        vulns.add(getTrend(project));
                    }
                    if (vulns.size()>0) {
                        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
                        if (!settings.isPresent()) {
                            throw new Exception("Settings error during sending email trend");
                        }
                        String body = templateBuilder.createTemplateEmail(vulns);
                        MimeMessage message = sender.createMimeMessage();
                        message.setSubject("Mixeway Security aggregated vulnerability trend update");
                        MimeMessageHelper helper = new MimeMessageHelper(message, true);
                        helper.setFrom(settings.get().getSmtpUsername() + "@" + settings.get().getDomain());
                        helper.setTo(email);
                        helper.setText(body, true);
                        sender.send(message);
                    }
                } catch( Exception e){
                     log.warn(e.getLocalizedMessage());
                }
            }

    }

    private Long createWebAppVulnHistory(Project p){
        return (long)webAppVulnRepository.findByWebAppInAndSeverityIn(p.getWebapps(),
                severities).size();

    }
    @Transactional
    public Long createCodeVulnHistory(Project p){
        try (Stream<CodeVuln> codeVulnStream = codeVulnRepository.findByCodeGroupInAndAnalysis(p.getCodes(), Constants.FORTIFY_ANALYSIS_EXPLOITABLE)){
            return codeVulnStream.count();
        }
    }
    private Long createInfraVulnHistory(Project p){
        return getInfraVulnsForProject(p);
    }
    private Long createAuditHistory(Project p){
        return (long)(nodeAuditRepository.findByNodeInAndScoreIn(p.getNodes(),scores).size());
    }

    private long getInfraVulnsForProject(Project project){
        long vulns;
        vulns = infrastructureVulnRepository.findByIntfInAndSeverityIn(
                interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets())), severities).size();
        return vulns;
    }

   List<EmailVulnHelper> getTrend(Project project) throws Exception {
        List<EmailVulnHelper> vulns = new ArrayList<>();
        List<VulnHistory> vulnsForProject = vulnHistoryRepository.getLastTwoVulnForProject(project.getId());
        vulnsForProject.sort(Comparator.comparing(VulnHistory::getInserted));
       //Network scan
       try {
           if (project.getAssets().size() > 0) {
               if (vulnsForProject.get(6).getInfrastructureVulnHistory() > vulnsForProject.get(0).getInfrastructureVulnHistory()) {
                   vulns.add(new EmailVulnHelper(project, (int) (vulnsForProject.get(6).getInfrastructureVulnHistory() - vulnsForProject.get(0).getInfrastructureVulnHistory()),
                           "Increased     (+", "Network Security Test", "red", vulnsForProject.get(6).getInserted(), vulnsForProject.get(0).getInserted(),
                           vulnsForProject.get(6).getInfrastructureVulnHistory().intValue()));
               } else if (vulnsForProject.get(6).getInfrastructureVulnHistory() < vulnsForProject.get(0).getInfrastructureVulnHistory()) {
                   vulns.add(new EmailVulnHelper(project, (int) (vulnsForProject.get(0).getInfrastructureVulnHistory() - vulnsForProject.get(6).getInfrastructureVulnHistory()),
                           "Decreased     (-", "Network Security Test", "green", vulnsForProject.get(6).getInserted(), vulnsForProject.get(0).getInserted(),
                           vulnsForProject.get(6).getInfrastructureVulnHistory().intValue()));
               } else
                   vulns.add(new EmailVulnHelper(project, 0,
                           "Not changed  (", "Network Security Test", "blue", vulnsForProject.get(6).getInserted(), vulnsForProject.get(0).getInserted(),
                           vulnsForProject.get(6).getInfrastructureVulnHistory().intValue()));
           }
           //Audit
           if (project.getNodes().size() > 0 ) {
               if (vulnsForProject.get(6).getAuditVulnHistory() > vulnsForProject.get(0).getAuditVulnHistory()) {
                   vulns.add(new EmailVulnHelper(project, (int) (vulnsForProject.get(6).getAuditVulnHistory() - vulnsForProject.get(0).getAuditVulnHistory()),
                           "Increased    (+", "CIS Compliance", "red", vulnsForProject.get(6).getInserted(), vulnsForProject.get(0).getInserted(),
                           vulnsForProject.get(6).getAuditVulnHistory().intValue()));
               } else if (vulnsForProject.get(6).getAuditVulnHistory() < vulnsForProject.get(0).getAuditVulnHistory()) {
                   vulns.add(new EmailVulnHelper(project, (int) (vulnsForProject.get(0).getAuditVulnHistory() - vulnsForProject.get(6).getAuditVulnHistory()),
                           "Decreased    (-", "CIS Compliance", "green", vulnsForProject.get(6).getInserted(), vulnsForProject.get(0).getInserted(),
                           vulnsForProject.get(6).getAuditVulnHistory().intValue()));
               } else
                   vulns.add(new EmailVulnHelper(project, 0,
                           "Not changed  (", "CIS Compliance", "blue", vulnsForProject.get(6).getInserted(), vulnsForProject.get(0).getInserted(),
                           vulnsForProject.get(6).getAuditVulnHistory().intValue()));
           }
           //CODE scan
           if ( project.getCodes().size() > 0) {
               if (vulnsForProject.get(6).getCodeVulnHistory() > vulnsForProject.get(0).getCodeVulnHistory()) {
                   vulns.add(new EmailVulnHelper(project, (int) (vulnsForProject.get(6).getCodeVulnHistory() - vulnsForProject.get(0).getCodeVulnHistory()),
                           "Increased    (+", "Static Source Code Security Audit", "red", vulnsForProject.get(6).getInserted(),
                           vulnsForProject.get(0).getInserted(), vulnsForProject.get(6).getCodeVulnHistory().intValue()));
               } else if (vulnsForProject.get(6).getCodeVulnHistory() < vulnsForProject.get(0).getCodeVulnHistory()) {
                   vulns.add(new EmailVulnHelper(project, (int) (vulnsForProject.get(0).getCodeVulnHistory() - vulnsForProject.get(6).getCodeVulnHistory()),
                           "Decreased    (-", "Static Source Code Security Audit", "green", vulnsForProject.get(6).getInserted(),
                           vulnsForProject.get(0).getInserted(), vulnsForProject.get(6).getCodeVulnHistory().intValue()));
               } else
                   vulns.add(new EmailVulnHelper(project, 0,
                           "Not changed  (", "Static Source Code Security Audit", "blue", vulnsForProject.get(6).getInserted(),
                           vulnsForProject.get(0).getInserted(), vulnsForProject.get(6).getCodeVulnHistory().intValue()));

               //OpenSource
               if (vulnsForProject.get(6).getSoftwarePacketVulnNumber() > vulnsForProject.get(0).getSoftwarePacketVulnNumber()) {
                   vulns.add(new EmailVulnHelper(project, (int) (vulnsForProject.get(6).getSoftwarePacketVulnNumber() - vulnsForProject.get(0).getSoftwarePacketVulnNumber()),
                           "Increased    (+", "OpenSource Scanner", "red", vulnsForProject.get(6).getInserted(),
                           vulnsForProject.get(0).getInserted(), vulnsForProject.get(6).getSoftwarePacketVulnNumber().intValue()));
               } else if (vulnsForProject.get(6).getSoftwarePacketVulnNumber() < vulnsForProject.get(0).getSoftwarePacketVulnNumber()) {
                   vulns.add(new EmailVulnHelper(project, (int) (vulnsForProject.get(0).getSoftwarePacketVulnNumber() - vulnsForProject.get(6).getSoftwarePacketVulnNumber()),
                           "Decreased    (-", "OpenSource Scanner", "green", vulnsForProject.get(6).getInserted(),
                           vulnsForProject.get(0).getInserted(), vulnsForProject.get(6).getSoftwarePacketVulnNumber().intValue()));
               } else
                   vulns.add(new EmailVulnHelper(project, 0,
                           "Not changed  (", "OpenSource Scanner", "blue", vulnsForProject.get(6).getInserted(),
                           vulnsForProject.get(0).getInserted(), vulnsForProject.get(6).getSoftwarePacketVulnNumber().intValue()));
           }
           //DAST
           if ( project.getWebapps().size() > 0 ) {
               if (vulnsForProject.get(6).getWebAppVulnHistory() > vulnsForProject.get(0).getWebAppVulnHistory()) {
                   vulns.add(new EmailVulnHelper(project, (int) (vulnsForProject.get(6).getWebAppVulnHistory() - vulnsForProject.get(0).getWebAppVulnHistory()),
                           "Increased    (+", "Dynamic Web Application Scanner", "red", vulnsForProject.get(6).getInserted(),
                           vulnsForProject.get(0).getInserted(), vulnsForProject.get(6).getWebAppVulnHistory().intValue()));
               } else if (vulnsForProject.get(6).getWebAppVulnHistory() < vulnsForProject.get(0).getWebAppVulnHistory()) {
                   vulns.add(new EmailVulnHelper(project, (int) (vulnsForProject.get(0).getWebAppVulnHistory() - vulnsForProject.get(6).getWebAppVulnHistory()),
                           "Decreased    (-", "Dynamic Web Application Scanner", "green", vulnsForProject.get(6).getInserted(),
                           vulnsForProject.get(0).getInserted(), vulnsForProject.get(6).getWebAppVulnHistory().intValue()));
               } else
                   vulns.add(new EmailVulnHelper(project, 0,
                           "Not changed  (", "Dynamic Web Application Scanner", "blue", vulnsForProject.get(6).getInserted(),
                           vulnsForProject.get(0).getInserted(), vulnsForProject.get(6).getWebAppVulnHistory().intValue()));
           }

       } catch (IndexOutOfBoundsException e){
           throw new Exception("Cannot create Trend Email not enough data");
       }
       return vulns;
    }
}
