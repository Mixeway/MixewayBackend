package io.mixeway.db.entity;

import javax.persistence.*;

import io.mixeway.integrations.webappscan.plugin.burpee.model.Issue;
import io.mixeway.integrations.webappscan.plugin.burpee.model.IssueDetail;
import io.mixeway.pojo.Vulnerability;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@Entity
@EntityScan
@Table(name = "webappvuln")
@EntityListeners(AuditingEntityListener.class)
@Cacheable
@org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
public class WebAppVuln implements Vulnerability {

	private Long id;
	@JsonIgnore private WebAppScan webAppScan;
	private WebApp webApp;
	@JsonIgnore private CodeProject codeProject;
	private String name;
	private String description;
	private String recommendation;
	private String location;
	private String severity;
	private Status status;
	private String ticketId;

	public WebAppVuln(){};

	/**
	 * Used for burp loadVulnerabilities
	 *
	 * @param webApp which contains vuln
	 * @param issue get from burp REST API
	 */
    public WebAppVuln(WebApp webApp, Issue issue){
    	this.webApp = webApp;
    	this.description = issue.getDescription();
    	this.name = issue.getName();
    	this.severity = StringUtils.capitalize(issue.getSeverity());
    	this.location = issue.getOrigin()+issue.getPath();
	}

    @Column(name="ticketid")
	public String getTicketId() {
		return ticketId;
	}

	public void setTicketId(String ticketId) {
		this.ticketId = ticketId;
	}



	@ManyToOne(fetch = FetchType.EAGER, optional = true)
	@JoinColumn(name = "status_id", nullable = true)
	@OnDelete(action = OnDeleteAction.CASCADE)
	public Status getStatus() {
		return status;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	@ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "webappscan_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public WebAppScan getWebAppScan() {
		return webAppScan;
	}
	public void setWebAppScan(WebAppScan webAppScan) {
		this.webAppScan = webAppScan;
	}
	@ManyToOne(fetch = FetchType.EAGER, optional = true, cascade=CascadeType.DETACH)
    @JoinColumn(name = "webapp_id", nullable = true)
	public WebApp getWebApp() {
		return webApp;
	}
	public void setWebApp(WebApp webApp) {
		this.webApp = webApp;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public String getRecommendation() {
		return recommendation;
	}
	public void setRecommendation(String recommendation) {
		this.recommendation = recommendation;
	}
	public String getLocation() {
		return location;
	}
	public void setLocation(String location) {
		this.location = location;
	}
	public String getSeverity() {
		return severity;
	}
	public void setSeverity(String severity) {
		this.severity = severity;
	}

	@ManyToOne(fetch = FetchType.LAZY, optional = true, cascade=CascadeType.DETACH)
	@JoinColumn(name = "codeproject_id", nullable = true)
	@JsonIgnore
	public CodeProject getCodeProject() {
		return codeProject;
	}

	public void setCodeProject(CodeProject codeProject) {
		this.codeProject = codeProject;
	}
}
