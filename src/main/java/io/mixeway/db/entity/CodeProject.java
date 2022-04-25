package io.mixeway.db.entity;

import java.util.Objects;
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
@Table(
		name = "codeproject",
		indexes = {
				@Index(columnList = "id",name="codeproject_index")
		})@EntityListeners(AuditingEntityListener.class)
public class CodeProject implements VulnSource {
	private Long id;
	private String name;
	private String dTrackUuid;
	@JsonIgnore private Set<ProjectVulnerability> vulns;
	@JsonIgnore private String commitid;
	@JsonIgnore private String repoUrl;
	@JsonIgnore private String repoUsername;
	@JsonIgnore private String repoPassword;
	@JsonIgnore private String technique;
	@JsonIgnore private Boolean skipAllScan;
	@JsonIgnore private String additionalPath;
	@JsonIgnore private Boolean inQueue;
	@JsonIgnore private Set<SoftwarePacket> softwarePackets;
	private String branch;
	@JsonIgnore
	private String requestId;
	private int risk;
	private Boolean enableJira;
	@JsonIgnore
	private int versionIdAll;
	@JsonIgnore
	private int versionIdsingle;
	@JsonIgnore
	private String jobId;
	@JsonIgnore
	private String scanid;
	@JsonIgnore private String scope;
	@JsonIgnore private int remoteid;
	private String appClient;

	@JsonIgnore
	private Project project;

	public void setProject(Project project) {
		this.project = project;
	}


	@Column(name="versionidall")
	public int getVersionIdAll() {
		return versionIdAll;
	}

	public void setVersionIdAll(int versionIdAll) {
		this.versionIdAll = versionIdAll;
	}

	@Column(name="versionidsingle")
	public int getVersionIdsingle() {
		return versionIdsingle;
	}

	public void setVersionIdsingle(int versionIdsingle) {
		this.versionIdsingle = versionIdsingle;
	}

	@Column(name="jobid")
	public String getJobId() {
		return jobId;
	}

	public void setJobId(String jobId) {
		this.jobId = jobId;
	}


	public String getScanid() {
		return scanid;
	}

	public void setScanid(String scanid) {
		this.scanid = scanid;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	public int getRemoteid() {
		return remoteid;
	}

	public void setRemoteid(int remoteid) {
		this.remoteid = remoteid;
	}

	@Column(name="appclient")
	public String getAppClient() {
		return appClient;
	}

	public void setAppClient(String appClient) {
		this.appClient = appClient;
	}

	@Column(name = "enablejira")
	public Boolean getEnableJira() {
		return enableJira;
	}

	public void setEnableJira(Boolean enableJira) {
		this.enableJira = enableJira;
	}

	/**
	 * For CICD
	 */
	public CodeProject(String projectName, String branch, String commitid) {
		this.name = projectName;
		this.branch = branch;
		this.commitid = commitid;
		this.skipAllScan = true;
		this.inQueue = false;

	}

	public CodeProject() {

	}

	public int getRisk() {
		return risk;
	}

	public void setRisk(int risk) {
		this.risk = risk;
	}

	@Column(name="dtrackuuid")
	public String getdTrackUuid() {
		return dTrackUuid;
	}

	public void setdTrackUuid(String dTrackUuid) {
		this.dTrackUuid = dTrackUuid;
	}

	@Column(name="requestid")
	public String getRequestId() {
		return requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	public String getBranch() {
		return branch;
	}

	public void setBranch(String branch) {
		this.branch = branch;
	}

	@ManyToMany(fetch = FetchType.LAZY,
			cascade = CascadeType.ALL)
	@JoinTable(name = "codeproject_softwarepacket",
			joinColumns = { @JoinColumn(name = "codeproject_id") },
			inverseJoinColumns = { @JoinColumn(name = "softwarepacket_id") })
	public Set<SoftwarePacket> getSoftwarePackets() {
		return softwarePackets;
	}
	public void setSoftwarePackets(Set<SoftwarePacket> softwarePackets) {
		this.softwarePackets = softwarePackets;
	}

	private Boolean running;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "project_id", nullable = false)
	@OnDelete(action = OnDeleteAction.CASCADE)
	public Project getProject() {
		return project;
	}

	public Boolean getRunning() {
		return running;
	}

	public void setRunning(Boolean running) {
		this.running = running;
	}

	@Column(name = "inqueue")
	public Boolean getInQueue() {
		return inQueue;
	}

	public void setInQueue(Boolean inQueue) {
		this.inQueue = inQueue;
	}


	public String getCommitid() {
		return commitid;
	}

	public void setCommitid(String commitid) {
		this.commitid = commitid;
	}

	@Column(name = "additionalpath")
	public String getAdditionalPath() {
		return additionalPath;
	}

	public void setAdditionalPath(String additionalPath) {
		this.additionalPath = additionalPath;
	}

	@Column(name = "skipallscan")
	public Boolean getSkipAllScan() {
		return skipAllScan;
	}

	public void setSkipAllScan(Boolean skipAllScan) {
		this.skipAllScan = skipAllScan;
	}

	public String getTechnique() {
		return technique;
	}

	public void setTechnique(String technique) {
		this.technique = technique;
	}

	@Column(name = "repourl")
	public String getRepoUrl() {
		return repoUrl;
	}

	public void setRepoUrl(String repoUrl) {
		this.repoUrl = repoUrl;
	}
	@Column(name="repousername")
	public String getRepoUsername() {
		return repoUsername;
	}

	public void setRepoUsername(String repoUsername) {
		this.repoUsername = repoUsername;
	}
	@Column(name="repopassword")
	public String getRepoPassword() {
		return repoPassword;
	}

	public void setRepoPassword(String repoPassword) {
		this.repoPassword = repoPassword;
	}

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	@OneToMany(mappedBy = "codeProject", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	public Set<ProjectVulnerability> getVulns() {
		return vulns;
	}
	public void setVulns(Set<ProjectVulnerability> vulns) {
		this.vulns = vulns;
	}


	@PreUpdate
	void preUpdate(){
		if (running == null)
			running = false;
	}
	@PrePersist
	void prePersist(){
		if (running == null)
			running = false;
		if (enableJira==null)
			enableJira=false;
	}
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof CodeProject)) return false;
		CodeProject book = (CodeProject) o;
		return Objects.equals(getId(), book.getId());
	}

	@Override
	public int hashCode() {
		return getClass().hashCode();
	}

}
