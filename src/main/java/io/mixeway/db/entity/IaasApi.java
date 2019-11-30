package io.mixeway.db.entity;

import java.io.Serializable;

import javax.persistence.*;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@EntityScan
@Table(name = "iaasapi")
@EntityListeners(AuditingEntityListener.class)
public class IaasApi implements Serializable{
	
    private Long id;
    private String iamUrl;
    private String serviceUrl;
    private String networkUrl;
    private String domain;
    private String username;
    private String password;
    private String tenantId;
    private Project project;
    private String token;
    private String tokenExpires;
    private Boolean enabled;
    private Boolean status;
    private Boolean external;
    private RoutingDomain routingDomain;
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	@Column(name = "iamurl")
	public String getIamUrl() {
		return iamUrl;
	}

	public void setIamUrl(String iamUrl) {
		this.iamUrl = iamUrl;
	}

	@Column(name = "serviceurl")
	public String getServiceUrl() {
		return serviceUrl;
	}

	public void setServiceUrl(String serviceUrl) {
		this.serviceUrl = serviceUrl;
	}

	@Column(name="networkurl")
	public String getNetworkUrl() {
		return networkUrl;
	}

	@Column
	public void setNetworkUrl(String networkUrl) {
		this.networkUrl = networkUrl;
	}

	@Column
	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	@Column
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Column
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	@Column(name="tenantid")
	public String getTenantId() {
		return tenantId;
	}

	public void setTenantId(String tenantId) {
		this.tenantId = tenantId;
	}

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "project_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public Project getProject() {
		return project;
	}

	public void setProject(Project project) {
		this.project = project;
	}

	@Column(name = "token")
	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
	@Column(name="tokenexpires")
	public String getTokenExpires() {
		return tokenExpires;
	}

	public void setTokenExpires(String tokenExpires) {
		this.tokenExpires = tokenExpires;
	}
	@Column(name="enabled")
	public Boolean getEnabled() {
		return enabled;
	}

	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}
	@Column(name="status")
	public Boolean getStatus() {
		return status;
	}

	public void setStatus(Boolean status) {
		this.status = status;
	}
	@Column(name="external")
	public Boolean getExternal() {
		return external;
	}

	public void setExternal(Boolean external) {
		this.external = external;
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

	@PreRemove
	private void removeIaasApi() {
		project.getIaasApis().remove(this);
	}

}
