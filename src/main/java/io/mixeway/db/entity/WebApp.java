package io.mixeway.db.entity;

import java.util.Set;

import javax.persistence.*;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@EntityScan
@EntityListeners(AuditingEntityListener.class)
@Table(name = "webapp", uniqueConstraints={@UniqueConstraint(columnNames = "url")})
public class WebApp {
	
	private Long id;
	private Project project;
	private String url;
	@JsonIgnore private LoginSequence loginSequence;
	@JsonIgnore private String loqinSequenceUploadUrl;
	private String lastExecuted;
	@JsonIgnore private String targetId;
	@JsonIgnore private String scanId;
	@JsonIgnore private Boolean publicscan;
	@JsonIgnore private Boolean readyToScan;
	private Boolean running;
	@JsonIgnore private Set<WebAppHeader> headers;
	@JsonIgnore private Set<WebAppCookies> webAppCookies;
	@JsonIgnore private Set<WebAppVuln> vulns;
	@JsonIgnore private Asset asset;
	@JsonIgnore private Boolean inQueue;
	private String lastscan;
	@JsonIgnore private String inserted;
	@JsonIgnore private CodeGroup codeGroup;
	@JsonIgnore private CodeProject codeProject;
	@JsonIgnore private Boolean autoStart;
	@JsonIgnore private String requestId;

	@Column(name="requestid")
	public String getRequestId() {
		return requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	@OneToMany(mappedBy = "webApp", cascade = CascadeType.ALL, fetch=FetchType.EAGER)
	public Set<WebAppCookies> getWebAppCookies() {
		return webAppCookies;
	}

	public void setWebAppCookies(Set<WebAppCookies> webAppCookies) {
		this.webAppCookies = webAppCookies;
	}

	@Column(name = "autostart")
	public Boolean getAutoStart() {
		return autoStart;
	}

	public void setAutoStart(Boolean autoStart) {
		this.autoStart = autoStart;
	}

	@ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "codegroup_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public CodeGroup getCodeGroup() {
		return codeGroup;
	}
	public void setCodeGroup(CodeGroup codeGroup) {
		this.codeGroup = codeGroup;
	}
	@ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "codeproject_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public CodeProject getCodeProject() {
		return codeProject;
	}
	public void setCodeProject(CodeProject codeProject) {
		this.codeProject = codeProject;
	}
	public String getInserted() {
		return inserted;
	}
	public void setInserted(String inserted) {
		this.inserted = inserted;
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
    @JoinColumn(name = "project_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public Project getProject() {
		return project;
	}
	public void setProject(Project project) {
		this.project = project;
	}
	@Column(unique = true)
	public String getUrl() {
		return url;
	}
	public void setUrl(String url) {
		this.url = url;
	}
	@ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "loginsequence_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public LoginSequence getLoginSequence() {
		return loginSequence;
	}
	public void setLoginSequence(LoginSequence loginSequence) {
		this.loginSequence = loginSequence;
	}
	@Column(name="lastexecuted")
	public String getLastExecuted() {
		return lastExecuted;
	}
	public void setLastExecuted(String lastExecuted) {
		this.lastExecuted = lastExecuted;
	}
	@Column(name="target_id")
	public String getTargetId() {
		return targetId;
	}
	public void setTargetId(String targetId) {
		this.targetId = targetId;
	}
	public Boolean getPublicscan() {
		return publicscan;
	}
	public void setPublicscan(Boolean publicscan) {
		this.publicscan = publicscan;
	}
	@Column(name="loginsequenceuploadurl")
	public String getLoqinSequenceUploadUrl() {
		return loqinSequenceUploadUrl;
	}
	public void setLoqinSequenceUploadUrl(String loqinSequenceUploadUrl) {
		this.loqinSequenceUploadUrl = loqinSequenceUploadUrl;
	}
	@Column(name="readytoscan")
	public Boolean getReadyToScan() {
		return readyToScan;
	}
	public void setReadyToScan(Boolean readyToScan) {
		this.readyToScan = readyToScan;
	}
	public Boolean getRunning() {
		return running;
	}
	public void setRunning(Boolean running) {
		this.running = running;
	}
	@Column(name="scanid")
	public String getScanId() {
		return scanId;
	}
	public void setScanId(String scanId) {
		this.scanId = scanId;
	}
	@OneToMany(mappedBy = "webApp", cascade = CascadeType.ALL, fetch=FetchType.EAGER)
	public Set<WebAppHeader> getHeaders() {
		return headers;
	}
	public void setHeaders(Set<WebAppHeader> headers) {
		this.headers = headers;
	}
	@OneToMany(mappedBy = "webApp", cascade = CascadeType.DETACH, fetch=FetchType.LAZY)
	public Set<WebAppVuln> getVulns() {
		return vulns;
	}
	public void setVulns(Set<WebAppVuln> vulns) {
		this.vulns = vulns;
	}
	@ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "asset_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public Asset getAsset() {
		return asset;
	}
	public void setAsset(Asset asset) {
		this.asset = asset;
	}
	@Column(name="inqueue")
	public Boolean getInQueue() {
		return inQueue;
	}
	public void setInQueue(Boolean inQueue) {
		this.inQueue = inQueue;
	}
	public String getLastscan() {
		return lastscan;
	}
	public void setLastscan(String lastscan) {
		this.lastscan = lastscan;
	}
}
