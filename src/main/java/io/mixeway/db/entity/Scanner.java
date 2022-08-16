package io.mixeway.db.entity;

import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@EntityScan
@Table(name = "nessus")
@EntityListeners(AuditingEntityListener.class)
public class Scanner {
	private Long id;
	@JsonIgnore private String accessKey;
	private String team;
	@JsonIgnore private String secretKey;
	private String apiUrl;
	@JsonIgnore private String network;
	@JsonIgnore private Proxies proxies;
	private Boolean status;
	@JsonIgnore private String scannerid;
	@JsonIgnore private Set<NessusScanTemplate> nessusScanTemplates;
	@JsonIgnore private Set<NessusScanner> nessusScanner;
	private Boolean usePublic;
	@JsonIgnore private int folderId;
	@JsonIgnore private String username;
	@JsonIgnore private String password;
	@JsonIgnore private String configId;
	private RoutingDomain routingDomain;
	private ScannerType scannerType;
	@JsonIgnore private String apiKey;
	@JsonIgnore private String fortifytoken;
	@JsonIgnore private String fortifytokenexpiration;
	private String rfwUrl;
	@JsonIgnore private String rfwUser;
	@JsonIgnore private String rfwPassword;
	@JsonIgnore private String template;
	@JsonIgnore private Integer engineId;
	@JsonIgnore private String rfwScannerIp;
	private int runningScans;

	@Column(name = "runningscans")
	public int getRunningScans() {
		return runningScans;
	}

	public void setRunningScans(int runningScans) {
		this.runningScans = runningScans;
	}

	public String getTeam() {
		return team;
	}

	public void setTeam(String team) {
		this.team = team;
	}

	@Column(name="rfwscannerip")
	public String getRfwScannerIp() {
		return rfwScannerIp;
	}

	public void setRfwScannerIp(String rfwScannerIp) {
		this.rfwScannerIp = rfwScannerIp;
	}

	public String getTemplate() {
		return template;
	}

	public void setTemplate(String template) {
		this.template = template;
	}
	@Column(name="engineid")
	public Integer getEngineId() {
		return engineId;
	}

	public void setEngineId(Integer engineId) {
		this.engineId = engineId;
	}

	@Column(name="rfwurl")
	public String getRfwUrl() {
		return rfwUrl;
	}

	public void setRfwUrl(String rfwUrl) {
		this.rfwUrl = rfwUrl;
	}
	@Column(name="rfwuser")
	public String getRfwUser() {
		return rfwUser;
	}

	public void setRfwUser(String rfwUser) {
		this.rfwUser = rfwUser;
	}
	@Column(name="rfwpassword")
	public String getRfwPassword() {
		return rfwPassword;
	}

	public void setRfwPassword(String rfwPassword) {
		this.rfwPassword = rfwPassword;
	}

	public String getFortifytoken() {
		return fortifytoken;
	}
	public void setFortifytoken(String fortifytoken) {
		this.fortifytoken = fortifytoken;
	}
	public String getFortifytokenexpiration() {
		return fortifytokenexpiration;
	}
	public void setFortifytokenexpiration(String fortifytokenexpiration) {
		this.fortifytokenexpiration = fortifytokenexpiration;
	}
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	@Column(name="accesskey")
	public String getAccessKey() {
		return accessKey;
	}
	public void setAccessKey(String accessKey) {
		this.accessKey = accessKey;
	}
	@Column(name="secretkey")
	public String getSecretKey() {
		return secretKey;
	}
	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}
	@Column(name="apiurl")
	public String getApiUrl() {
		return apiUrl;
	}
	public void setApiUrl(String apiUrl) {
		this.apiUrl = apiUrl;
	}
	public String getNetwork() {
		return network;
	}
	public void setNetwork(String network) {
		this.network = network;
	}
	@ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "proxies_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public Proxies getProxies() {
		return proxies;
	}
	public void setProxies(Proxies proxies) {
		this.proxies = proxies;
	}
	public Boolean getStatus() {
		return status;
	}
	public void setStatus(Boolean status) {
		this.status = status;
	}
	public String getScannerid() {
		return scannerid;
	}
	public void setScannerid(String scannerid) {
		this.scannerid = scannerid;
	}
	@OneToMany(mappedBy = "nessus", cascade = CascadeType.ALL)
	public Set<NessusScanTemplate> getNessusScanTemplates() {
		return nessusScanTemplates;
	}
	public void setNessusScanTemplates(Set<NessusScanTemplate> nessusScanTemplates) {
		this.nessusScanTemplates = nessusScanTemplates;
	}
	@OneToMany(mappedBy = "nessus", cascade = CascadeType.ALL)
	public Set<NessusScanner> getNessusScanner() {
		return nessusScanner;
	}
	public void setNessusScanner(Set<NessusScanner> nessusScanner) {
		this.nessusScanner = nessusScanner;
	}
	@Column(name="usepublic")
	public Boolean getUsePublic() {
		return usePublic;
	}
	public void setUsePublic(Boolean usePublic) {
		this.usePublic = usePublic;
	}
	@Column(name="folderid")
	public int getFolderId() {
		return folderId;
	}
	public void setFolderId(int folderId) {
		this.folderId = folderId;
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

	@Column(name="configid")
	public String getConfigId() {
		return configId;
	}
	public void setConfigId(String configId) {
		this.configId = configId;
	}
	@ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "routingdomain_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public RoutingDomain getRoutingDomain() {
		return routingDomain;
	}

	public void setRoutingDomain(RoutingDomain routingDomain) {
		this.routingDomain = routingDomain;
	}
	@ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "scannertype_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public ScannerType getScannerType() {
		return scannerType;
	}
	public void setScannerType(ScannerType scannerType) {
		this.scannerType = scannerType;
	}
	@Column(name="apikey")
	public String getApiKey() {
		return apiKey;
	}
	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}
	
	

}
