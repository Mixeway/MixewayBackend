package io.mixeway.db.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Entity
@EntityScan
@Table(name = "vulnhistory")
@EntityListeners(AuditingEntityListener.class)
public class VulnHistory {
	private Long id;
	private Long infrastructureVulnHistory;
	private Long webAppVulnHistory;
	private Long codeVulnHistory;
	private Long auditVulnHistory;
	private Long softwarePacketVulnNumber;
	private String name;
	private String inserted;
	private Project project;

	@Column(name = "softwarepacketvulnnumber")
	public Long getSoftwarePacketVulnNumber() {
		return softwarePacketVulnNumber;
	}

	public void setSoftwarePacketVulnNumber(Long softwarePacketVulnNumber) {
		this.softwarePacketVulnNumber = softwarePacketVulnNumber;
	}

	@Column(name="infrastructurevulnnumber")
	public Long getInfrastructureVulnHistory() {
		return infrastructureVulnHistory;
	}

	public void setInfrastructureVulnHistory(Long infrastructureVulnHistory) {
		this.infrastructureVulnHistory = infrastructureVulnHistory;
	}
	@Column(name="webappvulnnumber")
	public Long getWebAppVulnHistory() {
		return webAppVulnHistory;
	}

	public void setWebAppVulnHistory(Long webAppVulnHistory) {
		this.webAppVulnHistory = webAppVulnHistory;
	}
	@Column(name="codevulnnumber")
	public Long getCodeVulnHistory() {
		return codeVulnHistory;
	}

	public void setCodeVulnHistory(Long codeVulnHistory) {
		this.codeVulnHistory = codeVulnHistory;
	}
	@Column(name="auditvulnnumber")
	public Long getAuditVulnHistory() {
		return auditVulnHistory;
	}

	public void setAuditVulnHistory(Long auditVulnHistory) {
		this.auditVulnHistory = auditVulnHistory;
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
	public String getInserted() {
		return inserted;
	}
	public void setInserted(String inserted) {
		this.inserted = inserted;
	}
	@ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id")
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public Project getProject() {
		return project;
	}
	public void setProject(Project project) {
		this.project = project;
	}

	public Long findMaxVulns(){
		List<Long> values = new ArrayList<Long>(){{
			add(getWebAppVulnHistory());
			add(getAuditVulnHistory());
			add(getInfrastructureVulnHistory());
			add(getCodeVulnHistory());
		}};

		return Collections.max(values);
	}

	public Long findMinVulns(){
		List<Long> values = new ArrayList<Long>(){{
			add(getWebAppVulnHistory());
			add(getAuditVulnHistory());
			add(getInfrastructureVulnHistory());
			add(getCodeVulnHistory());
		}};

		return Collections.min(values);
	}
	
	

}
