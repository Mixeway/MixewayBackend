package io.mixeway.db.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@EntityScan
@Table(name = "users")
@EntityListeners(AuditingEntityListener.class)
public class User {
	
	private Long id;
	private String commonName;
	private String permisions;
	private String lastLoggedDate;
	private String lastLoggedIp;
	private Boolean enabled;
	private String username;
	private int logins;
	private int failedLogins;

	public int getLogins() {
		return logins;
	}

	public void setLogins(int logins) {
		this.logins = logins;
	}

	@Column(name = "failedlogins")
	public int getFailedLogins() {
		return failedLogins;
	}

	public void setFailedLogins(int failedLogins) {
		this.failedLogins = failedLogins;
	}

	@JsonIgnore private String password;

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

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	@Column(name="commonname", unique=true)
	public String getCommonName() {
		return commonName;
	}
	public void setCommonName(String commonName) {
		this.commonName = commonName;
	}
	public String getPermisions() {
		return permisions;
	}
	public void setPermisions(String permisions) {
		this.permisions = permisions;
	}
	@Column(name="lastloggeddate")
	public String getLastLoggedDate() {
		return lastLoggedDate;
	}
	public void setLastLoggedDate(String lastLoggedDate) {
		this.lastLoggedDate = lastLoggedDate;
	}
	@Column(name="lastloggedip")
	public String getLastLoggedIp() {
		return lastLoggedIp;
	}
	public void setLastLoggedIp(String lastLoggedIp) {
		this.lastLoggedIp = lastLoggedIp;
	}
	public Boolean getEnabled() {
		return enabled;
	}
	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}
	
	

}
