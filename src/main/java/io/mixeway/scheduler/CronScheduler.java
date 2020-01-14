package io.mixeway.scheduler;

import io.mixeway.db.entity.NessusScan;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.VulnHistory;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.remotefirewall.apiclient.RfwApiClient;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import io.mixeway.config.Constants;
import io.mixeway.plugins.remotefirewall.model.Rule;
import io.mixeway.rest.vulnmanage.service.GetVulnerabilitiesService;
import io.mixeway.pojo.DOPMailTemplateBuilder;
import io.mixeway.pojo.EmailVulnHelper;
import io.mixeway.pojo.ScanHelper;

import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.transaction.Transactional;
import java.io.FileNotFoundException;
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

@Component
@Transactional
public class CronScheduler {
    @Autowired
    VulnHistoryRepository vulnHistoryRepository;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    WebAppVulnRepository webAppVulnRepository;
    @Autowired
    CodeVulnRepository codeVulnRepository;
    @Autowired
    NodeAuditRepository nodeAuditRepository;
    @Autowired
    InfrastructureVulnRepository infrastructureVulnRepository;
    @Autowired
    InterfaceRepository interfaceRepository;
    @Autowired
    NessusScanRepository nessusScanRepository;
    @Autowired
    JavaMailSender sender;
    @Autowired
    SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;

    DOPMailTemplateBuilder templateBuilder = new DOPMailTemplateBuilder();
    List<String> severities = new ArrayList<String>(){{
        add("Medium" );
        add("High");
        add("Critical");
    }};
    List<String> scores = new ArrayList<String>(){{
        add("WARN" );
        add("FAIL");
    }};
    @Autowired
    RfwApiClient rfwApiClient;
    @Autowired
    ScannerRepository scannerRepository;
    @Autowired
    ScanHelper scanHelper;
    @Autowired
    GetVulnerabilitiesService getVulnerabilitiesService;


    private DateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final Logger log = LoggerFactory.getLogger(CronScheduler.class);

    // Every 12h
    @Scheduled(cron="0 0 12 * * *" )
    public void createHistoryForVulns() throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
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
        Long vulnNumbers = (long)softwarePacketVulnerabilityRepository.getSoftwareVulnsForCodeProject(project.getId()).size();

        return vulnNumbers;
    }

    //every 3 minutes
    @Scheduled(initialDelay=0,fixedDelay = 150000)
    public void verifyRFWRules() throws JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
        try {
            for (NessusScan ns : nessusScanRepository.getRunningScansWithRfwConfigured()) {
                List<Rule> rules = rfwApiClient.getListOfRules(ns.getNessus()).stream().filter(r -> r.getChain().equals("OUTPUT")).collect(Collectors.toList());
                List<String> runningScansIps = scanHelper.prepareTargetsForScan(ns, false);
                for (Rule r : rules) {
                    if (!runningScansIps.contains(r.getDestination()))
                        log.error("Security Violation! RFW Contains rule which is not valid in scope of running tests !! - {}", r.getDestination());
                }
            }
        } catch (NullPointerException ex) {}

    }
    //@Scheduled(cron = "0 0 14 * * FRI")
    public void sendEmailToDOP() throws Exception {
        Project tools= projectRepository.getOne((long)1);
        Project nonprod= projectRepository.getOne((long)4);
        Project prod= projectRepository.getOne((long)6);
        String body = templateBuilder.createTemplate(getTrend(tools,"OpenStack"),
                getTrend(nonprod,"OpenStack"), getTrend(prod,"OpenStack"),
                getTrend(tools,"scanners"));
        MimeMessage message = sender.createMimeMessage();
        try {
            message.setSubject("DOP Security test trend update");
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            //TODO settings helper create
            helper.setCc(InternetAddress.parse(tools.getContactList()));
            helper.setText(body, true);
            //sender.send(message);
        } catch (MessagingException ex){
            log.warn("MessagingException {}", ex.getLocalizedMessage());
        }

    }
    @Scheduled(cron = "0 0 14 * * FRI")
    public void sendTrendEmails(){
        List<Project> projects = projectRepository.findByContactListNotNull();
        for(Project project : projects){
            String body = null;
            try {
                body = templateBuilder.createTemplateEmail(getTrend(project,null));
                log.info(body);
            } catch (Exception e) {
                log.warn(e.getLocalizedMessage());
            }
        }
    }

    private Long createWebAppVulnHistory(Project p){
        return (long)webAppVulnRepository.findByWebAppInAndSeverityIn(p.getWebapps(),
                severities).size();

    }
    private Long createCodeVulnHistory(Project p){
        return (long)codeVulnRepository.findByCodeGroupInAndAnalysisNot(p.getCodes(), "Not an Issue").size();


    }
    private Long createInfraVulnHistory(Project p){
        return getInfraVulnsForProject(p);
    }
    private Long createAuditHistory(Project p){
        return (long)(nodeAuditRepository.findByNodeInAndScoreIn(p.getNodes(),scores).size());
    }

    private long getInfraVulnsForProject(Project project){
        long vulns = 0;
        vulns = (long)infrastructureVulnRepository.findByIntfInAndSeverityIn(
                interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets())), severities).size();
        return vulns;
    }

   List<EmailVulnHelper> getTrend(Project project, String source) throws Exception {
        List<EmailVulnHelper> vulns = new ArrayList<>();
       List<VulnHistory> vulnsForProject = vulnHistoryRepository.getLastTwoVulnForProject(project.getId());
       vulnsForProject.sort(Comparator.comparing(VulnHistory::getInserted));
       //Network scan
       try {
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
           //Audit
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
           //CODE scan
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
           //DAST
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
       } catch (IndexOutOfBoundsException e){
           throw new Exception("Cannot create Trend Email not enouvh data");
       }
       return vulns;
    }
}
