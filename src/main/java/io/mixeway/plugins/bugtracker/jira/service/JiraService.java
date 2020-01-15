package io.mixeway.plugins.bugtracker.jira.service;

import com.atlassian.jira.rest.client.api.IssueRestClient;
import com.atlassian.jira.rest.client.api.JiraRestClient;
import com.atlassian.jira.rest.client.api.JiraRestClientFactory;
import com.atlassian.jira.rest.client.api.domain.Issue;
import com.atlassian.jira.rest.client.api.domain.IssueFieldId;
import com.atlassian.jira.rest.client.api.domain.input.*;
import com.atlassian.jira.rest.client.internal.async.AsynchronousJiraRestClientFactory;
import io.atlassian.util.concurrent.Promise;
import io.mixeway.db.entity.*;
import io.mixeway.pojo.LogUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import io.mixeway.config.Constants;
import io.mixeway.db.repository.BugTrackerRepository;
import io.mixeway.plugins.bugtracker.BugTracking;
import io.mixeway.pojo.Status;
import io.mixeway.pojo.Vulnerability;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;

@Service
public class JiraService implements BugTracking {
    private static final Logger log = LoggerFactory.getLogger(JiraService.class);
    private final VaultOperations operations;
    private final BugTrackerRepository bugTrackerRepository;

    @Autowired
    JiraService(VaultOperations operations, BugTrackerRepository bugTrackerRepository){
        this.operations = operations;
        this.bugTrackerRepository = bugTrackerRepository;
    }

    @Override
    public String createIssue(String title, String description, BugTracker bugTracker) throws URISyntaxException {
        Properties origProp;
        Properties proxyProp;
        origProp = System.getProperties();
        if (bugTracker.getProxies() != null) {
            proxyProp = new Properties(origProp);
            proxyProp.setProperty("http.proxyHost", bugTracker.getProxies().getIp());
            proxyProp.setProperty("http.proxyPort", bugTracker.getProxies().getPort());
        }
        origProp.setProperty("jsse.enableSNIExtension","false");
        JiraRestClientFactory factory = new AsynchronousJiraRestClientFactory();
        String password = operations.read("secret/"+bugTracker.getPassword()).getData().get("password").toString();
        URI uri = new URI(bugTracker.getUrl());

        JiraRestClient client = factory.createWithBasicHttpAuthentication(uri, bugTracker.getUsername(), password);
        IssueRestClient issueClient = client.getIssueClient();
        IssueInput newIssue;
        if (bugTracker.getAsignee() != null) {
            newIssue = new IssueInputBuilder(bugTracker.getProjectId(), Long.valueOf(bugTracker.getIssueType()), title)
                    .setDescription(description)
                    .setFieldInput(new FieldInput(IssueFieldId.ASSIGNEE_FIELD, ComplexIssueInputFieldValue.with("name", bugTracker.getAsignee())))
                    .build();
        } else {
            newIssue = new IssueInputBuilder(bugTracker.getProjectId(), Long.valueOf(bugTracker.getIssueType()), title)
                    .setDescription(description)
                    .build();
        }
        //TODO uncomment it
        //String ticketId = issueClient.createIssue(newIssue) .claim().getKey();
        System.setProperties(origProp);
        return null;
    }
    @Override
    public <T extends JpaRepository, V extends Vulnerability> ResponseEntity<Status> processRequest(T o, Optional<V> entity, BugTracker bugTracker, Project project, String vulnType, String principal, Boolean manual) throws URISyntaxException {
        if (entity.isPresent()  && entity.get().getTicketId()==null && canIssueTicket(manual,entity.get(),bugTracker.getAutoStrategy())){
            entity.get().setTicketId(this.createIssue(entity.get().getName(),entity.get().getDescription(),bugTracker));
            o.save(entity.get());
            log.info("{} - Issued ticket for {} for {} vulns {}", LogUtil.prepare(principal), LogUtil.prepare(project.getName()), LogUtil.prepare(bugTracker.getVulns()), LogUtil.prepare(entity.get().getName()));
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);

        }
    }

    @Override
    public boolean canProcessRequest(BugTracker bugTracker) {
        return bugTracker.getBugTrackerType().getName().equals(Constants.JIRA);
    }

    @Override
    public void closeIssue(String ticketId, BugTracker bugTracker) throws URISyntaxException {
        JiraRestClientFactory factory = new AsynchronousJiraRestClientFactory();
        String password = Objects.requireNonNull(Objects.requireNonNull(operations.read("secret/" + bugTracker.getPassword())).getData()).get("password").toString();
        URI uri = new URI(bugTracker.getUrl());
        JiraRestClient client = factory.createWithBasicHttpAuthentication(uri, bugTracker.getUsername(), password);
        Promise promise = client.getIssueClient().getIssue("ticketId");
        Issue issue = (Issue) promise.claim();
        TransitionInput transitionInput = new TransitionInput(251);
        client.getIssueClient().transition(issue, transitionInput);
    }
    private <V extends Vulnerability> void getDetailsForClosingIssue(V vulnerability){
        if (vulnerability instanceof WebAppVuln){
            Optional<BugTracker> bugTracker = bugTrackerRepository.findByProjectAndVulns(((WebAppVuln) vulnerability).getWebApp().getProject(),Constants.VULN_JIRA_WEBAPP);
            if (bugTracker.isPresent()){

            }
        } else if (vulnerability instanceof InfrastructureVuln){
            Optional<BugTracker> bugTracker = bugTrackerRepository.findByProjectAndVulns(((InfrastructureVuln) vulnerability).getIntf().getAsset().getProject(),Constants.VULN_JIRA_INFRASTRUCTURE);
        } else if (vulnerability instanceof CodeVuln){
            Optional<BugTracker> bugTracker = bugTrackerRepository.findByProjectAndVulns(((CodeVuln) vulnerability).getCodeGroup().getProject(),Constants.VULN_JIRA_CODE);
        } else if (vulnerability instanceof SoftwarePacketVulnerability){
            Optional<BugTracker> bugTracker = bugTrackerRepository.findByProjectAndVulns(((SoftwarePacketVulnerability) vulnerability).getProject(),Constants.VULN_JIRA_OPENSOURCE);

        }
    }

    @Override
    public <V extends Vulnerability> Boolean canIssueTicket(boolean mode, V vulnerability, String issueStrategy){
        if (mode){
            return true;
        } else if (issueStrategy.equals(Constants.VULN_CRITICALITY_HIGH)){
            if (vulnerability instanceof CodeVuln){
                return (((CodeVuln) vulnerability).getAnalysis().equals(Constants.FORTIFY_ANALYSIS_EXPLOITABLE) && vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)) ;
            } else {
                return vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH);
            }
        } else if (issueStrategy.equals("Medium")){
            if (vulnerability instanceof CodeVuln){
                return (((CodeVuln) vulnerability).getAnalysis().equals(Constants.FORTIFY_ANALYSIS_EXPLOITABLE) &&
                        (vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH) || vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM ))) ;
            } else {
                return (vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH) || vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM ));
            }
        } else if (issueStrategy.equals("Low")){
            if (vulnerability instanceof CodeVuln){
                return (((CodeVuln) vulnerability).getAnalysis().equals(Constants.FORTIFY_ANALYSIS_EXPLOITABLE) &&
                        (vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH) || vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM ) ||
                                vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_LOW ))) ;
            } else {
                return (vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH) || vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM ) ||
                        vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_LOW ));
            }
        }
        return false;
    }
}
