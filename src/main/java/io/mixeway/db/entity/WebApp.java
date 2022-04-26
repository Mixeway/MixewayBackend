package io.mixeway.db.entity;

import java.util.Set;

import javax.persistence.*;

import io.mixeway.utils.VulnSource;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@EntityScan
@EntityListeners(AuditingEntityListener.class)
@Table(name = "webapp", uniqueConstraints={@UniqueConstraint(columnNames = {"url", "project_id"})})
public class WebApp implements VulnSource {
	
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
	@JsonIgnore private Set<ProjectVulnerability> vulns;
	@JsonIgnore private Asset asset;
	@JsonIgnore private Boolean inQueue;
	private String lastscan;
	@JsonIgnore private String inserted;
	@JsonIgnore private CodeProject codeProject;
	@JsonIgnore private Boolean autoStart;
	@JsonIgnore private String requestId;
	private RoutingDomain routingDomain;
	private String origin;
	@JsonIgnore String username;
	@JsonIgnore String password;
	private int priority;
	private String appClient;

	@Column(name="appclient")
	public String getAppClient() {
		return appClient;
	}

	public void setAppClient(String appClient) {
		this.appClient = appClient;
	}

	public int getPriority() {
		return priority;
	}

	public void setPriority(int priority) {
		this.priority = priority;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getOrigin() {
		return origin;
	}

	public void setOrigin(String origin) {
		this.origin = origin;
	}

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "routingdomain_id")
	public RoutingDomain getRoutingDomain() {
		return routingDomain;
	}

	public void setRoutingDomain(RoutingDomain routingDomain) {
		this.routingDomain = routingDomain;
	}

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
	public Set<ProjectVulnerability> getVulns() {
		return vulns;
	}
	public void setVulns(Set<ProjectVulnerability> vulns) {
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
	private int risk;

	public int getRisk() {
		return risk;
	}

	public void setRisk(int risk) {
		this.risk = risk;
	}
	@PrePersist
	public void webAppPrePersist(){
		if (inQueue == null)
				inQueue = false;
	}


}
