package io.mixeway.integrations.bugtracker.plugin.jira.service;

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
import io.mixeway.pojo.VaultHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.config.Constants;
import io.mixeway.db.repository.BugTrackerRepository;
import io.mixeway.integrations.bugtracker.BugTracking;
import io.mixeway.pojo.Status;
import io.mixeway.pojo.Vulnerability;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.Properties;

@Service
public class JiraService implements BugTracking {
    private static final Logger log = LoggerFactory.getLogger(JiraService.class);
    private final VaultHelper vaultHelper;
    private final BugTrackerRepository bugTrackerRepository;

    JiraService(VaultHelper vaultHelper, BugTrackerRepository bugTrackerRepository){
        this.vaultHelper = vaultHelper;
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
        String password =vaultHelper.getPassword(bugTracker.getPassword());
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
    public <T extends JpaRepository> ResponseEntity<Status> processRequest(T o, Optional<ProjectVulnerability> entity, BugTracker bugTracker, Project project, String vulnType, String principal, Boolean manual) throws URISyntaxException {
        if (entity.isPresent()  && entity.get().getTicketId()==0 && canIssueTicket(manual, entity.get() ,bugTracker.getAutoStrategy())){
            entity.get().setTicketId(Integer.parseInt(this.createIssue(entity.get().getVulnerability().getName(),entity.get().getDescription(),bugTracker)));
            o.save(entity.get());
            log.info("{} - Issued ticket for {} for {} vulns {}", LogUtil.prepare(principal), LogUtil.prepare(project.getName()), LogUtil.prepare(bugTracker.getVulns()), LogUtil.prepare(entity.get().getVulnerability().getName()));
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
        String password = vaultHelper.getPassword(bugTracker.getPassword());
        URI uri = new URI(bugTracker.getUrl());
        JiraRestClient client = factory.createWithBasicHttpAuthentication(uri, bugTracker.getUsername(), password);
        Promise promise = client.getIssueClient().getIssue("ticketId");
        Issue issue = (Issue) promise.claim();
        TransitionInput transitionInput = new TransitionInput(251);
        client.getIssueClient().transition(issue, transitionInput);
    }
    private void getDetailsForClosingIssue(ProjectVulnerability vulnerability){
        Optional<BugTracker> bugTracker = bugTrackerRepository.findByProjectAndVulns(vulnerability.getProject(),Constants.VULN_JIRA_OPENSOURCE);
    }

    @Override
    public Boolean canIssueTicket(boolean mode, ProjectVulnerability vulnerability, String issueStrategy){
        if (mode){
            return true;
        } else if (issueStrategy.equals(Constants.VULN_CRITICALITY_HIGH)){
            return vulnerability.getGrade() == 1 && vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH);
        } else if (issueStrategy.equals("Medium")){
            return vulnerability.getGrade() == 1 && (vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH) || vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM ));
        } else if (issueStrategy.equals("Low")){
            return vulnerability.getGrade() == 1 && (vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH) || vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM ) ||
                    vulnerability.getSeverity().equals(Constants.VULN_CRITICALITY_LOW ));
        }
        return false;
    }
}
