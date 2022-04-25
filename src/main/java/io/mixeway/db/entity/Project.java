package io.mixeway.db.entity;

import java.io.Serializable;
import java.util.Objects;
import java.util.Set;

import javax.persistence.*;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.Proxy;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;


@Entity
@EntityScan
@Table(name = "project")
@EntityListeners(AuditingEntityListener.class)
@Proxy(lazy=false)
public class Project implements Serializable{
	
    private Long id;
	
    private String name;
    @JsonIgnore
	Set<User> users;
    
    @JsonIgnore private String ciid;

	@JsonIgnore private String description;

	@JsonIgnore private Set<IaasApi> iaasApis;

	@JsonIgnore private Set<Asset> assets;
	@JsonIgnore private Set<Node> nodes;
	@JsonIgnore private Set<InfraScan> scans;
	@JsonIgnore private Set<CodeProject> codes;
	@JsonIgnore private Set<WebApp> webapps;
	@JsonIgnore private Set<WebAppScan> webAppScan;
	@JsonIgnore private int highVuln;
	@JsonIgnore private int mediumVuln;
	@JsonIgnore private int lowVuln;
	@JsonIgnore private String contactList;
	@JsonIgnore private Boolean WebAppAutoDiscover;
	@JsonIgnore private Set<CiOperations> ciOperations;
	@JsonIgnore private boolean autoWebAppScan;
	@JsonIgnore private boolean autoCodeScan;
	@JsonIgnore private boolean autoInfraScan;
	@JsonIgnore private String apiKey;
	@JsonIgnore private Set<VulnHistory> vulnHistories;
	private int risk;
	private boolean enableVulnManage;
	private boolean vulnAuditorEnable;
	private String networkdc;
	private String appClient;
	@JsonIgnore private User owner;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "owner_id")
	public User getOwner() {
		return owner;
	}

	public void setOwner(User owner) {
		this.owner = owner;
	}

	public Project(){}
    public Project(String projectName, String description, boolean vulnAuditorEnable, String ciid, User user) {
		this.name = projectName;
		this.description = description;
		this.vulnAuditorEnable = vulnAuditorEnable;
		this.ciid = ciid;
		this.owner = user;
    }

    @Column(name="appclient")
	public String getAppClient() {
		return appClient;
	}

	public void setAppClient(String appClient) {
		this.appClient = appClient;
	}

	public String getNetworkdc() {
		return networkdc;
	}

	public void setNetworkdc(String networkdc) {
		this.networkdc = networkdc;
	}

	@Column(name = "vulnauditorenable")
	public boolean isVulnAuditorEnable() {
		return vulnAuditorEnable;
	}

	public void setVulnAuditorEnable(boolean vulnAuditorEnable) {
		this.vulnAuditorEnable = vulnAuditorEnable;
	}

	@Column(name = "enablevulnmanage")
	public boolean isEnableVulnManage() {
		return enableVulnManage;
	}

	public void setEnableVulnManage(boolean enableVulnManage) {
		this.enableVulnManage = enableVulnManage;
	}

	public int getRisk() {
		return risk;
	}

	public void setRisk(int risk) {
		this.risk = risk;
	}

	@ManyToMany(mappedBy = "projects")
	public Set<User> getUsers() {
		return users;
	}

	public void setUsers(Set<User> users) {
		this.users = users;
	}

	@Column(name = "autoinfrascan")
	public boolean isAutoInfraScan() {
		return autoInfraScan;
	}

	public void setAutoInfraScan(boolean autoInfraScan) {
		this.autoInfraScan = autoInfraScan;
	}

	@Column(name="apikey")
	public String getApiKey() {
		return apiKey;
	}

	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}

	@Column(name = "autocodescan")
	public boolean isAutoCodeScan() {
		return autoCodeScan;
	}

	public void setAutoCodeScan(boolean autoCodeScan) {
		this.autoCodeScan = autoCodeScan;
	}

	@Column(name="autowebappscan")
	public boolean isAutoWebAppScan() {
		return autoWebAppScan;
	}

	public void setAutoWebAppScan(boolean autoWebAppScan) {
		this.autoWebAppScan = autoWebAppScan;
	}

	@OneToMany(mappedBy = "project", cascade = CascadeType.ALL, fetch= FetchType.LAZY)
	public Set<CiOperations> getCiOperations() {
		return ciOperations;
	}

	public void setCiOperations(Set<CiOperations> ciOperations) {
		this.ciOperations = ciOperations;
	}

	@Column(name="webappautodiscover")
	public Boolean getWebAppAutoDiscover() {
		return WebAppAutoDiscover;
	}

	public void setWebAppAutoDiscover(Boolean webAppAutoDiscover) {
		WebAppAutoDiscover = webAppAutoDiscover;
	}

	@Column(name="contactlist")
	public String getContactList() {
		return contactList;
	}

	public void setContactList(String contactList) {
		this.contactList = contactList;
	}

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}
	
	@Column(nullable = false)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
	@Column(nullable = true)
	public String getDescription() {
		return description;
	}

	public void setDescription(String desc) {
		this.description = desc;
	}
	
	@OneToMany(mappedBy = "project", cascade = CascadeType.ALL)
	public Set<IaasApi> getIaasApis() {
		return iaasApis;
	}

	public void setIaasApis(Set<IaasApi> iaasApis) {
		this.iaasApis = iaasApis;
	}
	
	@OneToMany(mappedBy = "project", cascade = CascadeType.ALL, fetch= FetchType.LAZY)
	public Set<Asset> getAssets() {
		return assets;
	}

	public void setAssets(Set<Asset> assets) {
		this.assets = assets;
	}
	@Column(name = "ciid")
	public String getCiid() {
		return ciid;
	}

	public void setCiid(String ciid) {
		this.ciid = ciid;
	}

	@OneToMany(mappedBy = "project", cascade = CascadeType.ALL)
	public Set<Node> getNodes() {
		return nodes;
	}

	public void setNodes(Set<Node> nodes) {
		this.nodes = nodes;
	}
	@OneToMany(mappedBy = "project", cascade = CascadeType.ALL)
	public Set<InfraScan> getScans() {
		return scans;
	}

	public void setScans(Set<InfraScan> scans) {
		this.scans = scans;
	}

	@OneToMany(mappedBy = "project", cascade = CascadeType.ALL, fetch=FetchType.EAGER)
	public Set<CodeProject> getCodes() {
		return codes;
	}

	public void setCodes(Set<CodeProject> codes) {
		this.codes = codes;
	}
	@OneToMany(mappedBy = "project", cascade = CascadeType.ALL, fetch=FetchType.LAZY)
	public Set<WebApp> getWebapps() {
		return webapps;
	}

	public void setWebapps(Set<WebApp> webapps) {
		this.webapps = webapps;
	}
	@OneToMany(mappedBy = "project", cascade = CascadeType.ALL, fetch=FetchType.LAZY)
	public Set<WebAppScan> getWebAppScan() {
		return webAppScan;
	}

	public void setWebAppScan(Set<WebAppScan> webAppScan) {
		this.webAppScan = webAppScan;
	}
	@Transient
	public int getHighVuln() {
		return highVuln;
	}

	public void setHighVuln(int highVuln) {
		this.highVuln = highVuln;
	}
	@Transient
	public int getMediumVuln() {
		return mediumVuln;
	}

	public void setMediumVuln(int mediumVuln) {
		this.mediumVuln = mediumVuln;
	}
	@Transient
	public int getLowVuln() {
		return lowVuln;
	}

	public void setLowVuln(int lowVuln) {
		this.lowVuln = lowVuln;
	}

	@OneToMany(mappedBy = "project", cascade = CascadeType.DETACH, fetch=FetchType.LAZY)
	public Set<VulnHistory> getVulnHistories() {
		return vulnHistories;
	}

	public void setVulnHistories(Set<VulnHistory> vulnHistories) {
		this.vulnHistories = vulnHistories;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof Project)) return false;
		Project p = (Project) o;
		return Objects.equals(getId(), p.getId());
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((name == null) ? 0 : name.hashCode());
		return result;
	}
	@Override
	public String toString(){
		return name;
	}

}
