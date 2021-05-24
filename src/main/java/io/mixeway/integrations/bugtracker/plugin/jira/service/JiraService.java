package io.mixeway.integrations.bugtracker.plugin.jira.service;

import com.atlassian.jira.rest.client.api.IssueRestClient;
import com.atlassian.jira.rest.client.api.JiraRestClient;
import com.atlassian.jira.rest.client.api.JiraRestClientFactory;
import com.atlassian.jira.rest.client.api.domain.*;
import com.atlassian.jira.rest.client.api.domain.input.*;
import com.atlassian.jira.rest.client.internal.async.AsynchronousJiraRestClientFactory;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Project;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.VaultHelper;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.config.Constants;
import io.mixeway.integrations.bugtracker.BugTracking;
import io.mixeway.pojo.Status;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.StreamSupport;

@Service
public class JiraService implements BugTracking {
    private static final Logger log = LoggerFactory.getLogger(JiraService.class);
    private final VaultHelper vaultHelper;

    JiraService(VaultHelper vaultHelper){
        this.vaultHelper = vaultHelper;
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
        Iterable<Priority> basicPriorities =  client.getMetadataClient().getPriorities().claim();
        Priority priority = StreamSupport.stream(basicPriorities.spliterator(), false).filter(t->t.getName().equals("A")).findFirst().orElse(null);
        IssueInput newIssue;
        if (bugTracker.getAsignee() != null) {
            newIssue = new IssueInputBuilder(bugTracker.getProjectId(), Long.valueOf(bugTracker.getIssueType()), title)
                    .setDescription(description)
                    .setPriority(priority)
                    .setFieldInput(new FieldInput(IssueFieldId.ASSIGNEE_FIELD, ComplexIssueInputFieldValue.with("email", bugTracker.getAsignee())))
                    .build();
        } else {
            newIssue = new IssueInputBuilder(bugTracker.getProjectId(), Long.valueOf(bugTracker.getIssueType()), title)
                    .setDescription(description)
                    .setPriority(priority)
                    .build();
        }
        //TODO uncomment it
        String ticketId = issueClient.createIssue(newIssue) .claim().getKey();
        System.setProperties(origProp);
        return ticketId;
    }
    @Override
    public <T extends JpaRepository> ResponseEntity<Status> processRequest(T o, Optional<ProjectVulnerability> entity, BugTracker bugTracker, Project project, String vulnType, String principal, Boolean manual) throws URISyntaxException {
        if (entity.isPresent()  && StringUtils.isBlank(entity.get().getTicketId()) && canIssueTicket(manual, entity.get() ,bugTracker.getAutoStrategy())){
            String title = buildTitle(entity.get());
            String description = buildDescription(entity.get());
            entity.get().setTicketId(this.createIssue(title,description,bugTracker));
            o.save(entity.get());
            log.info("{} - Issued ticket for {} for {} vulns {}", LogUtil.prepare(principal), LogUtil.prepare(project.getName()), LogUtil.prepare(bugTracker.getVulns()), LogUtil.prepare(entity.get().getVulnerability().getName()));
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);

        }
    }

    //TODO
    @Override
    public <T extends JpaRepository> ResponseEntity<Status> processRequestMultiVuln(T o, List<ProjectVulnerability> entity, BugTracker bugTracker, Project project, String vulnType, String principal, Boolean manual) throws URISyntaxException {
        //remove
        entity.removeIf(pv -> StringUtils.isNotBlank(pv.getTicketId()));
        if ( entity.size() > 0 ){
            String title = buildTitle(entity.stream().findFirst().get());
            String description = buildDescriptionMulti(entity);
            String ticketId = this.createIssue(title,description,bugTracker);
            entity.forEach(pv -> pv.setTicketId(ticketId));
            o.saveAll(entity);
            log.info("[BugTracker] Issuing ticket with {} vulnerabilities for project {}",
                    entity.stream().filter(pv -> pv.getTicketId().isEmpty()).count(),
                    LogUtil.prepare(project.getName()));
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);

        }
    }

    private String buildDescriptionMulti(List<ProjectVulnerability> projectVulnerability) {
        StringBuilder stringBuilder = new StringBuilder();
        assert projectVulnerability.size()>0;
        switch (projectVulnerability.stream().findFirst().get().getVulnerabilitySource().getName()) {
            case Constants.VULN_TYPE_SOURCECODE:
                stringBuilder.append("Vulnerability Name: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getVulnerabilitySource().getName());
                stringBuilder.append("\n\n");
                stringBuilder.append("Asset affected: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getCodeProject().getName());
                stringBuilder.append("\n\n");
                stringBuilder.append("File: ");
                for (ProjectVulnerability pv : projectVulnerability){
                    stringBuilder.append(pv.getLocation()).append("\n");
                }
                stringBuilder.append("\n\n");
                stringBuilder.append("Severity: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getSeverity());
                stringBuilder.append("\n\n");
                stringBuilder.append("Branch: ").append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getCodeProject().getBranch());
                stringBuilder.append("\n");
                stringBuilder.append("Commit: ").append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getCodeProject().getCommitid());
                stringBuilder.append("\n\n");
                stringBuilder.append("Description");
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getDescription(), "Description missing"));
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getRecommendation(), "No Recommendation avaliable"));
                return stringBuilder.toString();
            case Constants.VULN_TYPE_OPENSOURCE:
                stringBuilder.append("Library: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getLocation());
                stringBuilder.append("\n\n");
                stringBuilder.append("Asset affected: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getCodeProject().getName());
                stringBuilder.append("\n\n");
                stringBuilder.append("Vulnerabilities: ");
                for (ProjectVulnerability pv : projectVulnerability){
                    stringBuilder.append(pv.getVulnerability().getName()).append("\n");
                }
                stringBuilder.append("\n\n");
                stringBuilder.append("Severity: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getSeverity());
                stringBuilder.append("\n\n");
                stringBuilder.append("Branch: ").append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getCodeProject().getBranch());
                stringBuilder.append("\n");
                stringBuilder.append("Commit: ").append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getCodeProject().getCommitid());
                stringBuilder.append("\n\n");
                stringBuilder.append("Descriptions");
                stringBuilder.append("\n");
                stringBuilder.append("Avaliable at Mixeway (mixer.corpnet.pl)");
                return stringBuilder.toString();
            case Constants.VULN_TYPE_WEBAPP:
                stringBuilder.append("Vulnerability Name: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getVulnerabilitySource().getName());
                stringBuilder.append("\n\n");
                stringBuilder.append("Asset affected: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getWebApp().getUrl());
                stringBuilder.append("\n\n");
                stringBuilder.append("URLs affected: ");
                for (ProjectVulnerability pv : projectVulnerability){
                    stringBuilder.append(pv.getLocation()).append("\n");
                }
                stringBuilder.append("\n\n");
                stringBuilder.append("Severity: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getSeverity());
                stringBuilder.append("\n\n");
                stringBuilder.append("Description");
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getDescription(), "Description missing"));
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getRecommendation(), "No Recommendation avaliable"));
                return stringBuilder.toString();
            case Constants.VULN_TYPE_NETWORK:
                stringBuilder.append("Vulnerability Name: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getVulnerabilitySource().getName());
                stringBuilder.append("\n\n");
                stringBuilder.append("Asset affected: ").append("\n");
                for (ProjectVulnerability pv : projectVulnerability){
                    stringBuilder.append(pv.getLocation()).append("\n");
                }
                stringBuilder.append("\n\n");
                stringBuilder.append("Severity: ");
                stringBuilder.append(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getSeverity());
                stringBuilder.append("\n\n");
                stringBuilder.append("Description");
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getDescription(), "Description missing"));
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getRecommendation(), "No Recommendation avaliable"));
                return stringBuilder.toString();
            default:
                return projectVulnerability.stream().findFirst().orElse(new ProjectVulnerability()).getVulnerability().getDescription();
        }
    }

    private String buildDescription(ProjectVulnerability projectVulnerability) {
        StringBuilder stringBuilder = new StringBuilder();

        switch (projectVulnerability.getVulnerabilitySource().getName()) {
            case Constants.VULN_TYPE_SOURCECODE:
                stringBuilder.append("Vulnerability Name: ");
                stringBuilder.append(projectVulnerability.getVulnerability().getName());
                stringBuilder.append("\n\n");
                stringBuilder.append("Asset affected: ");
                stringBuilder.append(projectVulnerability.getCodeProject().getName());
                stringBuilder.append("\n\n");
                stringBuilder.append("File: ");
                stringBuilder.append(projectVulnerability.getLocation());
                stringBuilder.append("\n\n");
                stringBuilder.append("Severity: ");
                stringBuilder.append(projectVulnerability.getSeverity());
                stringBuilder.append("\n\n");
                stringBuilder.append("Description");
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.getDescription(), "Description missing"));
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.getRecommendation(), "No Recommendation avaliable"));
                return stringBuilder.toString();
            case Constants.VULN_TYPE_OPENSOURCE:
                stringBuilder.append("Vulnerability Name: ");
                stringBuilder.append(projectVulnerability.getVulnerability().getName());
                stringBuilder.append("\n\n");
                stringBuilder.append("Asset affected: ");
                stringBuilder.append(projectVulnerability.getCodeProject().getName());
                stringBuilder.append("\n\n");
                stringBuilder.append("Library: ");
                stringBuilder.append(projectVulnerability.getLocation());
                stringBuilder.append("\n\n");
                stringBuilder.append("Severity: ");
                stringBuilder.append(projectVulnerability.getSeverity());
                stringBuilder.append("\n\n");
                stringBuilder.append("Description");
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.getDescription(), "Description missing"));
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.getRecommendation(), "No Recommendation avaliable"));
                return stringBuilder.toString();
            case Constants.VULN_TYPE_WEBAPP:
                stringBuilder.append("Vulnerability Name: ");
                stringBuilder.append("\n\n");
                stringBuilder.append("Asset affected: ");
                stringBuilder.append(projectVulnerability.getWebApp().getUrl());
                stringBuilder.append("\n\n");
                stringBuilder.append("Library: ");
                stringBuilder.append(projectVulnerability.getLocation());
                stringBuilder.append("\n\n");
                stringBuilder.append("Severity: ");
                stringBuilder.append(projectVulnerability.getSeverity());
                stringBuilder.append("\n\n");
                stringBuilder.append("Description");
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.getDescription(), "Description missing"));
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.getRecommendation(), "No Recommendation avaliable"));
                return stringBuilder.toString();
            case Constants.VULN_TYPE_NETWORK:
                stringBuilder.append("Vulnerability Name: ");
                stringBuilder.append(projectVulnerability.getVulnerability().getName());
                stringBuilder.append("\n\n");
                stringBuilder.append("Asset affected: ");
                stringBuilder.append(projectVulnerability.getWebApp().getUrl());
                stringBuilder.append("\n\n");
                stringBuilder.append("Library: ");
                stringBuilder.append(projectVulnerability.getLocation());
                stringBuilder.append("\n\n");
                stringBuilder.append("Severity: ");
                stringBuilder.append(projectVulnerability.getSeverity());
                stringBuilder.append("\n\n");
                stringBuilder.append("Description");
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.getDescription(), "Description missing"));
                stringBuilder.append("\n");
                stringBuilder.append(Objects.toString(projectVulnerability.getRecommendation(), "No Recommendation avaliable"));
                return stringBuilder.toString();
            default:
                return projectVulnerability.getVulnerability().getDescription();
        }
    }

    private String buildTitle(ProjectVulnerability projectVulnerability) {
        switch (projectVulnerability.getVulnerabilitySource().getName()) {
            case Constants.VULN_TYPE_SOURCECODE:
                return String.format("[%s - %s] %s", projectVulnerability.getVulnerabilitySource().getName(),
                        projectVulnerability.getCodeProject().getName(),
                        projectVulnerability.getVulnerability().getName());
            case Constants.VULN_TYPE_OPENSOURCE:
                return String.format("[%s - %s] %s", projectVulnerability.getVulnerabilitySource().getName(),
                        projectVulnerability.getCodeProject().getName(),
                        projectVulnerability.getLocation());
            case Constants.VULN_TYPE_WEBAPP:
                return String.format("[%s - %s] %s", projectVulnerability.getVulnerabilitySource().getName(),
                        projectVulnerability.getWebApp().getUrl(),
                        projectVulnerability.getVulnerability().getName());
            case Constants.VULN_TYPE_NETWORK:
                return String.format("[%s - %s] %s", projectVulnerability.getVulnerabilitySource().getName(),
                        projectVulnerability.getAnInterface().getPrivateip(),
                        projectVulnerability.getVulnerability().getName());
            default:
                return projectVulnerability.getVulnerability().getName();
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

        Issue issue = client.getIssueClient().getIssue(ticketId).claim();
        Iterable<Transition> transitions = client.getIssueClient().getTransitions(issue.getTransitionsUri()).claim();
        Transition transition = StreamSupport.stream(transitions.spliterator(), false).filter(t->t.getName().equals("Gotowe")).findFirst().orElse(null);
        Comment closingMessage = Comment.valueOf("Vulnerabilities removed");
        assert transition != null;
        TransitionInput transitionInput = new TransitionInput(transition.getId(), null, closingMessage);
        client.getIssueClient().transition(issue.getTransitionsUri(), transitionInput).claim();
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
