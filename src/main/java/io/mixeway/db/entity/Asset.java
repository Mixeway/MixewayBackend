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
@Table(name = "asset")
@EntityListeners(AuditingEntityListener.class)
@Cacheable
@org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
public class Asset implements VulnSource {
	private Long id;
	private String name;
	@JsonIgnore private String assetId;
	private Project project;
	@JsonIgnore private String origin;
	@JsonIgnore private Boolean active;
	@JsonIgnore private Set<Interface> interfaces;
	@JsonIgnore private Set<SecurityGroup> securitygroup;
	@JsonIgnore private Set<Software> software;
	@JsonIgnore private Set<WebApp> webApps;
	@JsonIgnore private RoutingDomain routingDomain;
	@JsonIgnore private Set<SoftwarePacket> softwarePackets;
	@JsonIgnore private String os;
	@JsonIgnore private String osversion;
	@JsonIgnore private String fix;
	@JsonIgnore private String assetType;
	@JsonIgnore private String requestId;
	public Asset(){}

	public Asset(Instance instance, IaasApi iaasApi){
		this.setName(instance.getTags().stream().filter(p -> p.getKey().equals("Name")).findFirst().orElse(null).getValue());
		this.setActive(instance.getState().getName().equals(Constants.AWS_STATE_RUNNING));
		this.setProject(iaasApi.getProject());
		this.setRoutingDomain(iaasApi.getRoutingDomain());
		this.setOrigin(Constants.ORIGIN_API);
	}

	public Asset(NetworkInterface networkInterface, IaasApi iaasApi, RoutingDomain routingDomain) {
		this.setName(networkInterface.getPrivateDnsName());
		this.setActive(networkInterface.getStatus().equals(Constants.AWS_STATE_INUSE));
		this.setProject(iaasApi.getProject());
		this.setRoutingDomain(routingDomain);
		this.setOrigin(Constants.ORIGIN_API);
	}
	public Asset(String name, RoutingDomain routingDomain, Project project){
		this.setName(name);
		this.setActive(true);
		this.setProject(project);
		this.setRoutingDomain(routingDomain);
		this.setOrigin(Constants.ORIGIN_API);
	}

	@Column(name = "requestid")
	public String getRequestId() {
		return requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	@Column(name = "assettype")
	public String getAssetType() {
		return assetType;
	}
	public void setAssetType(String assetType) {
		this.assetType = assetType;
	}
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	
	@Column(name = "name")
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	
	@Column(name = "assetid")
	public String getAssetId() {
		return assetId;
	}
	public void setAssetId(String assetId) {
		this.assetId = assetId;
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
	@Column(name="origin")
	public String getOrigin() {
		return origin;
	}
	public void setOrigin(String origin) {
		this.origin = origin;
	}
	@OneToMany(mappedBy = "asset", fetch=FetchType.EAGER, orphanRemoval = true, cascade = CascadeType.ALL)
	public Set<Interface> getInterfaces() {
		return interfaces;
	}
	public void setInterfaces(Set<Interface> interfaces) {
		this.interfaces = interfaces;
	}
	@Column(name = "active")
	public Boolean getActive() {
		return active;
	}
	public void setActive(Boolean active) {
		this.active = active;
	}
	@ManyToMany(fetch = FetchType.LAZY,mappedBy="assets")
	public Set<SecurityGroup> getSecuritygroup() {
		return securitygroup;
	}
	public void setSecuritygroup(Set<SecurityGroup> securitygroup) {
		this.securitygroup = securitygroup;
	}
	@OneToMany(mappedBy = "asset", cascade = CascadeType.ALL, fetch=FetchType.LAZY)
	public Set<Software> getSoftware() {
		return software;
	}
	public void setSoftware(Set<Software> software) {
		this.software = software;
	}
	
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "routingdomain_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public RoutingDomain getRoutingDomain() {
		return routingDomain;
	}

	public void setRoutingDomain(RoutingDomain routingDomain) {
		this.routingDomain = routingDomain;
	}
	@OneToMany(mappedBy = "asset", cascade = CascadeType.ALL,fetch=FetchType.LAZY)
	public Set<WebApp> getWebApps() {
		return webApps;
	}
	public void setWebApps(Set<WebApp> webApps) {
		this.webApps = webApps;
	}
	@ManyToMany(fetch = FetchType.LAZY,
            cascade = {
                CascadeType.PERSIST,
                CascadeType.MERGE
            })
    @JoinTable(name = "asset_softwarepacket",
            joinColumns = { @JoinColumn(name = "asset_id") },
            inverseJoinColumns = { @JoinColumn(name = "softwarepacket_id") })
	public Set<SoftwarePacket> getSoftwarePackets() {
		return softwarePackets;
	}
	public void setSoftwarePackets(Set<SoftwarePacket> softwarePackets) {
		this.softwarePackets = softwarePackets;
	}
	public String getOs() {
		return os;
	}
	public void setOs(String os) {
		this.os = os;
	}
	public String getOsversion() {
		return osversion;
	}
	public void setOsversion(String osversion) {
		this.osversion = osversion;
	}
	public String getFix() {
		return fix;
	}
	public void setFix(String fix) {
		this.fix = fix;
	}
}
