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
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@EntityScan
@Table(name = "securitygroup")
@EntityListeners(AuditingEntityListener.class)
public class SecurityGroup {
	
	private Long id;
	private String name;
	private String securitygroupid;
	private Set<SecurityGroupRule> rules;
	private Set<Asset> assets;
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	@Column(name="name")
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	@Column(name="securitygroupid")
	public String getSecuritygroupid() {
		return securitygroupid;
	}
	public void setSecuritygroupid(String securitygroupid) {
		this.securitygroupid = securitygroupid;
	}
	@OneToMany(mappedBy = "securitygroup", cascade = CascadeType.ALL)
	public Set<SecurityGroupRule> getRules() {
		return rules;
	}
	public void setRules(Set<SecurityGroupRule> rules) {
		this.rules = rules;
	}
	


	@ManyToMany(fetch = FetchType.LAZY)
	@OnDelete(action = OnDeleteAction.CASCADE)
	@JoinTable(name = "asset_securitygroup", joinColumns = {@JoinColumn(name="securitygroup_id", referencedColumnName="id")}, 
				inverseJoinColumns= {@JoinColumn(name="asset_id", referencedColumnName="id")})
	public Set<Asset> getAssets() {
		return assets;
	}
	public void setAssets(Set<Asset> assets) {
		this.assets = assets;
	}
	

}
