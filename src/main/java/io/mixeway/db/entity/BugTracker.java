package io.mixeway.db.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

@Entity
@EntityScan
@Table(name = "bugtracker")
@EntityListeners(AuditingEntityListener.class)
@JsonIgnoreProperties(ignoreUnknown=true)
public class BugTracker {
    private Long id;
    private BugTrackerType bugTrackerType;
    private String url;
    private String username;
    private String password;
    private  String projectId;
    private  String issueType;
    private  String vulns;
    @JsonIgnore private Project project;
    private String autoStrategy;
    private String asignee;
    private Proxies proxies;
    private String epic;

    @ManyToOne(fetch = FetchType.EAGER, optional = true)
    @JoinColumn(name = "proxies_id", nullable = true)
    public Proxies getProxies() {
        return proxies;
    }

    public void setProxies(Proxies proxies) {
        this.proxies = proxies;
    }

    public String getAsignee() {
        return asignee;
    }

    public void setAsignee(String asignee) {
        this.asignee = asignee;
    }

    @Column(name = "autostrategy")
    public String getAutoStrategy() {
        return autoStrategy;
    }

    public void setAutoStrategy(String autoStrategy) {
        this.autoStrategy = autoStrategy;
    }

    public String getVulns() {
        return vulns;
    }

    public void setVulns(String vulns) {
        this.vulns = vulns;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "bugtrackertype_id", nullable = false)
    public BugTrackerType getBugTrackerType() {
        return bugTrackerType;
    }

    public void setBugTrackerType(BugTrackerType bugTrackerType) {
        this.bugTrackerType = bugTrackerType;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Column(name = "password")
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    @Column(name = "projectid")
    public String getProjectId() {
        return projectId;
    }

    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }
    @Column(name = "issuetype")
    public String getIssueType() {
        return issueType;
    }

    public void setIssueType(String issueType) {
        this.issueType = issueType;
    }
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "project_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public String getEpic() {
        return epic;
    }

    public void setEpic(String epic) {
        this.epic = epic;
    }
}
