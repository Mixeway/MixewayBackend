package io.mixeway.scheduler;

import io.mixeway.db.entity.*;
import io.mixeway.domain.service.infrascan.FindInfraScanService;
import io.mixeway.domain.service.intf.InterfaceOperations;
import io.mixeway.domain.service.intf.UpdateInterfaceService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.UpdateProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.GetOrCreateCodeProjectBranchService;
import io.mixeway.domain.service.scanmanager.code.UpdateCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.UpdateWebAppService;
import io.mixeway.domain.service.settings.GetSettingsService;
import io.mixeway.domain.service.vulnhistory.CreateVulnHistoryService;
import io.mixeway.domain.service.vulnhistory.FindVulnHistoryService;
import io.mixeway.scanmanager.integrations.remotefirewall.apiclient.RfwApiClient;
import io.mixeway.scanmanager.integrations.vulnauditor.service.MixewayVulnAuditorService;
import io.mixeway.scanmanager.service.opensource.OpenSourceScanService;
import io.mixeway.utils.DOPMailTemplateBuilder;
import io.mixeway.utils.EmailVulnHelper;
import io.mixeway.utils.ProjectRiskAnalyzer;
import io.mixeway.utils.ScanHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Transactional
@Log4j2
@RequiredArgsConstructor
public class GlobalScheduler {
    private final JavaMailSender sender;
    private final OpenSourceScanService openSourceScanService;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final FindProjectService findProjectService;
    private final CreateVulnHistoryService createVulnHistoryService;
    private final UpdateProjectService updateProjectService;
    private final InterfaceOperations interfaceOperations;
    private final UpdateWebAppService updateWebAppService;
    private final FindCodeProjectService findCodeProjectService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final GetSettingsService getSettingsService;
    private final FindVulnHistoryService findVulnHistoryService;
    private final FindInfraScanService findInfraScanService;
    private final UpdateInterfaceService updateInterfaceService;
    private final GetOrCreateCodeProjectBranchService getOrCreateCodeProjectBranchService;
    private final MixewayVulnAuditorService mixewayVulnAuditorService;


    private DOPMailTemplateBuilder templateBuilder = new DOPMailTemplateBuilder();
    private List<String> severities = new ArrayList<String>(){{
        add("Medium" );
        add("High");
        add("Critical");
    }};
    private List<String> critSeverities = new ArrayList<String>(){{
        add("High");
        add("Critical");
    }};


    @Scheduled(fixedDelay = 300000)
    public void predict() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        mixewayVulnAuditorService.perdictVulnerabilities();
    }


    /**
     * Interval: 12h
     * Create vuln history
     */
    @Scheduled(cron="0 0 12 * * *" )
    public void createHistoryForVulns() {
        for(Project project : findProjectService.findAll()){
            createVulnHistoryService.createScheduled(project);
        }
        log.info("History records for defined projects completed successfully.") ;

    }

    /**
     * Interval: 15min
     *
     * Get Vulns from OpenSource scanners - track
     */
    @Scheduled(initialDelay=3000,fixedDelay = 86400000)
    public void getDepTrackVulns() {
        log.info("[OpenSourceService] Starting loading vulnerabilities from SCA");
        int i =0;
        try {
            List<CodeProject> codeProjects = findCodeProjectService.getCodeProjectsWithOSIntegrationEnabled();
            log.info("[OpenSourceService] About to load info for {} projects", codeProjects.size());
            for (CodeProject cp : codeProjects){
                i++;
                if (i % 10 == 0) {
                    log.info("[OpenSourceService] Loading progress: {} / {}", i, codeProjects.size());
                }
                    try {

                        openSourceScanService.loadVulnerabilities(cp);
                    } catch (CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException e) {
                        log.error("Error {} during OpenSource Scan Synchro for {}", e.getLocalizedMessage(), cp.getName());
                    }
            }
        } catch (Exception ignored) {
            ignored.printStackTrace();
            log.error("Error during dTrack synchro {}", ignored.getLocalizedMessage());
        }
        log.info("[OpenSourceService] SCA Synchronization completed - vulnerabilities loaded");
    }

    /**
     * Interval: every 2 hours
     *
     * update project risk
     */
    @Scheduled(cron="0 0 */2 * * ?" )
    public void setRiskForProject() {
        for (Project p : findProjectService.findAll()){
            int risk = projectRiskAnalyzer.getProjectAuditRisk(p) +
                    projectRiskAnalyzer.getProjectInfraRisk(p) +
                    projectRiskAnalyzer.getProjectCodeRisk(p) +
                    projectRiskAnalyzer.getProjectWebAppRisk(p) +
                    projectRiskAnalyzer.getProjectOpenSourceRisk(p);
            updateProjectService.setRisk(p, risk);
        }
        log.info("Updater risks for projects");
    }
    /**
     *
     * update interface risk
     */
    @Scheduled(cron="0 10 23 * * ?" )
    public void setRiskForAssets() {
        interfaceOperations.setRiskForInterfaces();
        log.info("Updated risks for interfaces");
    }

    /**
     *
     * update webapp risk
     */
    @Scheduled(cron="0 15 3 * * ?" )
    public void setRiskForWebApps() {
        updateWebAppService.setRisk();
        log.info("Updated risks for webapps");
    }

    /**
     *
     * update codeproject risk
     */
    @Scheduled(cron="0 20 3 * * ?" )
    public void setRiskForCodeProject() {
        updateCodeProjectService.setRisk();
        log.info("Updated risks for codeprojects");
    }

    /**
     * RFW integration
     */
//    //every 3 minutes
//    //@Scheduled(initialDelay=0,fixedDelay = 150000)
//    public void verifyRFWRules() throws  KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
//        try {
//            for (NessusScan ns : nessusScanRepository.getRunningScansWithRfwConfigured()) {
//                List<Rule> rules = rfwApiClient.getListOfRules(ns.getNessus()).stream().filter(r -> r.getChain().equals("INPUT")).collect(Collectors.toList());
//                List<String> runningScansIps = scanHelper.prepareTargetsForScan(ns, false);
//                for (Rule r : rules) {
//                    if (!runningScansIps.contains(r.getDestination()))
//                        log.error("Security Violation! RFW Contains rule which is not valid in scope of running tests !! - {}", r.getDestination());
//                }
//            }
//        } catch (NullPointerException ignored) {}
//
//    }

    /**
     * Sending emails with trend informations
     */
    @Scheduled(cron = "#{@getTrendEmailExpression}")
    public void sendTrendEmails(){

            List<String> emailsToSend = findProjectService.getUniqueContactListEmails();
            for (String email : emailsToSend) {
                try {
                    List<List<EmailVulnHelper>> vulns = new ArrayList<>();
                    List<Project> projectForEmail = findProjectService.getUniqueContactListEmails(email);
                    for (Project project : projectForEmail) {
                        vulns.add(getTrend(project));
                    }
                    if (vulns.size()>0) {
                        Settings settings = getSettingsService.getSettings();
                        String body = templateBuilder.createTemplateEmail(vulns);
                        MimeMessage message = sender.createMimeMessage();
                        message.setSubject("Mixeway Security aggregated vulnerability trend update");
                        MimeMessageHelper helper = new MimeMessageHelper(message, true);
                        helper.setFrom(settings.getSmtpUsername() + "@" + settings.getDomain());
                        helper.setTo(email);
                        helper.setText(body, true);
                        sender.send(message);
                    }
                } catch( Exception e){
                     log.warn(e.getLocalizedMessage());
                }
            }

    }





   private List<EmailVulnHelper> getTrend(Project project) throws Exception {
        List<EmailVulnHelper> vulns = new ArrayList<>();
        List<VulnHistory> vulnsForProject = findVulnHistoryService.getLastTwoVulnForProject(project.getId());
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
    /**
     * Interval: 15min
     *
     * Deactivate scan on interfaces that have runningscan=true
     */
    @Scheduled(initialDelay=3000,fixedDelay = 1500000)
    public void deactivateScanRunning() {
        List<Project> projects = findProjectService.findProjectWithInterfaceWithScanRunning();

        for(Project project: projects){
            if (findInfraScanService.hasProjectNoInfraScanRunning(project)){
                log.info("[Cleaning service] Project {} has no running infra scan but have interface with runningscan=true, deactivating it", project.getName());
                updateInterfaceService.clearState(project);
            }
        }
    }
}
