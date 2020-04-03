package io.mixeway.db.entity;

import java.util.Set;

import javax.persistence.*;

import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@EntityScan
@Table(name = "interface")
@EntityListeners(AuditingEntityListener.class)
@Cacheable
@org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
public class Interface {

	@JsonIgnore private Long id;
	private String privateip;
	@JsonIgnore private String floatingip;
	@JsonIgnore private String subnetId;
	@JsonIgnore private String macaddr;
	@JsonIgnore private Boolean active;
	private Asset asset;
	@JsonIgnore private String networkTag;
	@JsonIgnore private Set<NessusScan> scans;
	@JsonIgnore private Set<InfrastructureVuln> vulns;
	@JsonIgnore private Set<Service> services;
	private RoutingDomain routingDomain;
	@JsonIgnore private int hostid;
	@JsonIgnore private String pool;
	@JsonIgnore private Boolean autoCreated;
	@JsonIgnore private boolean scanRunning;
	private int risk;

	public int getRisk() {
		return risk;
	}

	public void setRisk(int risk) {
		this.risk = risk;
	}

	@Column(name="scanrunning")
	public boolean isScanRunning() {
		return scanRunning;
	}

	public void setScanRunning(boolean scanRunning) {
		this.scanRunning = scanRunning;
	}

	@Column(name="pool")
	public String getPool() {
		return pool;
	}
	public void setPool(String pool) {
		this.pool = pool;
	}
	@Column(name="autocreated")
	public Boolean getAutoCreated() {
		return autoCreated;
	}
	public void setAutoCreated(Boolean autoCreated) {
		this.autoCreated = autoCreated;
	}
	public int getHostid() {
		return hostid;
	}
	public void setHostid(int hostid) {
		this.hostid = hostid;
	}
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	@Column(name="privateip")
	public String getPrivateip() {
		return privateip;
	}
	public void setPrivateip(String privateip) {
		this.privateip = privateip;
	}
	@Column(name="floatingip")
	public String getFloatingip() {
		return floatingip;
	}
	public void setFloatingip(String floatingip) {
		this.floatingip = floatingip;
	}
	@Column(name="subnetid")
	public String getSubnetId() {
		return subnetId;
	}
	public void setSubnetId(String subnetId) {
		this.subnetId = subnetId;
	}
	@Column(name="macaddr")
	public String getMacaddr() {
		return macaddr;
	}
	public void setMacaddr(String macaddr) {
		this.macaddr = macaddr;
	}
	@ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "asset_id", nullable = false)
	public Asset getAsset() {
		return asset;
	}
	public void setAsset(Asset asset) {
		this.asset = asset;
	}
	@Column(name="active")
	public Boolean getActive() {
		return active;
	}
	public void setActive(Boolean active) {
		this.active = active;
	}
	@Column(name="networktag")
	public String getNetworkTag() {
		return networkTag;
	}
	public void setNetworkTag(String networkTag) {
		this.networkTag = networkTag;
	}
	@ManyToMany(mappedBy = "interfaces", cascade = {CascadeType.PERSIST,CascadeType.MERGE,CascadeType.DETACH})
	public Set<NessusScan> getScans() {
		return scans;
	}
	public void setScans(Set<NessusScan> scans) {
		this.scans = scans;
	}
	@OneToMany(mappedBy = "intf", cascade = CascadeType.REMOVE,orphanRemoval=true,fetch=FetchType.LAZY)
	public Set<InfrastructureVuln> getVulns() {
		return vulns;
	}
	public void setVulns(Set<InfrastructureVuln> vulns) {
		this.vulns = vulns;
	}
	@ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "routingdomain_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public RoutingDomain getRoutingDomain() {
		return routingDomain;
	}

	public void setRoutingDomain(RoutingDomain routingDomain) {
		this.routingDomain = routingDomain;
	}
	@OneToMany(mappedBy = "anInterface", cascade = CascadeType.REMOVE,orphanRemoval=true,fetch=FetchType.LAZY)
	public Set<Service> getServices() {
		return services;
	}

	public void setServices(Set<Service> services) {
		this.services = services;
	}

}
