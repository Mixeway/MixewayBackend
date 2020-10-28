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
@Table(name = "codegroup")
@EntityListeners(AuditingEntityListener.class)
public class CodeGroup {
	private Long id;
	private Project project;
	private String name;
	@JsonIgnore private String basePath;
	@JsonIgnore private String gitUrl;
	@JsonIgnore private Set<CodeProject> projects;
	@JsonIgnore private Boolean hasProjects;
	@JsonIgnore private int versionIdAll;
	@JsonIgnore private int versionIdsingle;
	@JsonIgnore private String repoUrl;
	@JsonIgnore private String repoUsername;
	@JsonIgnore private String repoPassword;
	@JsonIgnore private boolean running;
	@JsonIgnore private boolean inQueue;
	@JsonIgnore private boolean auto;
	@JsonIgnore private String jobId;
	@JsonIgnore private String technique;
	@JsonIgnore private String requestid;
	@JsonIgnore private String scanid;
	@JsonIgnore private String scope;
	@JsonIgnore private int remoteid;
	private String appClient;

	public int getRemoteid() {
		return remoteid;
	}

	public void setRemoteid(int remoteid) {
		this.remoteid = remoteid;
	}

	public CodeGroup(){}
	/**
	 * For CICD
	 * @param project
	 * @param codeProjectName
	 */
	public CodeGroup(Project project, String codeProjectName) {
		this.project = project;
		this.name = codeProjectName;
		this.versionIdAll = 0;
		this.versionIdsingle = 0;
		this.running = false;
		this.inQueue = false;
		this.auto = false;
	}

	@Column(name="appclient")
	public String getAppClient() {
		return appClient;
	}

	public void setAppClient(String appClient) {
		this.appClient = appClient;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	public String getScanid() {
		return scanid;
	}

	public void setScanid(String scanid) {
		this.scanid = scanid;
	}

	public String getRequestid() {
		return requestid;
	}

	public void setRequestid(String requestid) {
		this.requestid = requestid;
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

	public String getTechnique() {
		return technique;
	}

	public void setTechnique(String technique) {
		this.technique = technique;
	}

	@Column(name="repourl")
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
	@Column(name="running")
	public boolean isRunning() {
		return running;
	}

	public void setRunning(boolean running) {
		this.running = running;
	}
	@Column(name="inqueue")
	public boolean isInQueue() {
		return inQueue;
	}

	public void setInQueue(boolean inQueue) {
		this.inQueue = inQueue;
	}
	@Column(name="auto")
	public boolean isAuto() {
		return auto;
	}

	public void setAuto(boolean auto) {
		this.auto = auto;
	}
	@Column(name="jobid")
	public String getJobId() {
		return jobId;
	}

	public void setJobId(String jobId) {
		this.jobId = jobId;
	}

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
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
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	@Column(name="basepath")
	public String getBasePath() {
		return basePath;
	}
	public void setBasePath(String basePath) {
		this.basePath = basePath;
	}
	@Column(name="giturl")
	public String getGitUrl() {
		return gitUrl;
	}
	public void setGitUrl(String gitUrl) {
		this.gitUrl = gitUrl;
	}
	@OneToMany(mappedBy = "codeGroup", cascade = CascadeType.ALL)
	public Set<CodeProject> getProjects() {
		return projects;
	}
	public void setProjects(Set<CodeProject> projects) {
		this.projects = projects;
	}
	@Column(name="hasprojects")
	public Boolean getHasProjects() {
		return hasProjects;
	}
	public void setHasProjects(Boolean hasProjects) {
		this.hasProjects = hasProjects;
	}

}
