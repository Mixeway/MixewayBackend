package io.mixeway.db.entity;

import java.util.Set;

import javax.persistence.*;

import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.NetworkInterface;
import io.mixeway.config.Constants;
import io.mixeway.utils.VulnSource;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@EntityScan
@Table(name = "interface",uniqueConstraints={@UniqueConstraint(columnNames = {"asset_id", "privateip"})})
@EntityListeners(AuditingEntityListener.class)
@Cacheable
@org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
public class Interface implements VulnSource {

	private Long id;
	private String privateip;
	@JsonIgnore private String floatingip;
	@JsonIgnore private String subnetId;
	@JsonIgnore private String macaddr;
	@JsonIgnore private Boolean active;
	private Asset asset;
	@JsonIgnore private String networkTag;
	@JsonIgnore private Set<InfraScan> scans;
	@JsonIgnore private Set<Service> services;
	private RoutingDomain routingDomain;
	@JsonIgnore private int hostid;
	@JsonIgnore private String pool;
	@JsonIgnore private Boolean autoCreated;
	@JsonIgnore private boolean scanRunning;
	private int risk;
	public Interface(){}
	public Interface(Instance instance, Asset asset, RoutingDomain routingDomain, boolean isPublic) {
		this.setActive(instance.getState().getName().equals(Constants.AWS_STATE_RUNNING));
		if (isPublic){
			this.setPrivateip(instance.getPublicIpAddress());
		} else {
			this.setPrivateip(instance.getPrivateIpAddress());
		}
		this.setAsset(asset);
		this.setRoutingDomain(routingDomain);
		this.setAutoCreated(false);
	}

    public Interface(NetworkInterface networkInterface, Asset asset, RoutingDomain routingDomain, boolean isPublic) {
		this.setActive(networkInterface.getStatus().equals(Constants.AWS_STATE_INUSE));
		if (isPublic){
			this.setPrivateip(networkInterface.getAssociation().getPublicIp());
		} else {
			this.setPrivateip(networkInterface.getPrivateIpAddress());
		}
		this.setAsset(asset);
		this.setRoutingDomain(routingDomain);
		this.setAutoCreated(false);
    }
    public Interface (Asset asset, String ip) {
		this.setActive(true);
		this.setAsset(asset);
		this.setPrivateip(ip);
		this.setRoutingDomain(asset.getRoutingDomain());
		this.setAutoCreated(false);
	}

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
	public Set<InfraScan> getScans() {
		return scans;
	}
	public void setScans(Set<InfraScan> scans) {
		this.scans = scans;
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
	@OneToMany(mappedBy = "anInterface", cascade = CascadeType.ALL,fetch=FetchType.LAZY)
	public Set<Service> getServices() {
		return services;
	}

	public void setServices(Set<Service> services) {
		this.services = services;
	}

}
