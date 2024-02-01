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
	private Long resolvedVulnerabilities;
	private Long avgTimeToFix;
	private Long percentResolvedCriticals;
	private Long codeCritVuln;
	private Long codeHighVuln;
	private Long codeMediumVuln;
	private Long codeLowVuln;
	private Long scaCritVuln;
	private Long scaHighVuln;
	private Long scaMediumVuln;
	private Long scaLowVuln;
	private Long webAppCritVuln;
	private Long webAppHighVuln;
	private Long webAppMediumVuln;
	private Long webAppLowVuln;
	private Long assetCritVuln;
	private Long assetHighVuln;
	private Long assetMediumVuln;
	private Long assetLowVuln;


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

	@Column(name="resolvedvulnerabilities")
	public Long getResolvedVulnerabilities() {
		return resolvedVulnerabilities;
	}

	public void setResolvedVulnerabilities(Long resolvedVulnerabilities) {
		this.resolvedVulnerabilities = resolvedVulnerabilities;
	}

	@Column(name="avgtimetofix")
	public Long getAvgTimeToFix() {
		return avgTimeToFix;
	}

	public void setAvgTimeToFix(Long avgTimeToFix) {
		this.avgTimeToFix = avgTimeToFix;
	}

	@Column(name="percentresolvedcriticals")
	public Long getPercentResolvedCriticals() {
		return percentResolvedCriticals;
	}

	public void setPercentResolvedCriticals(Long percentResolvedCriticals) {
		this.percentResolvedCriticals = percentResolvedCriticals;
	}

	@Column(name="codecritvuln")
	public Long getCodeCritVuln() {
		return codeCritVuln;
	}

	public void setCodeCritVuln(Long codeCritVuln) {
		this.codeCritVuln = codeCritVuln;
	}

	@Column(name="codehighvuln")
	public Long getCodeHighVuln() {
		return codeHighVuln;
	}

	public void setCodeHighVuln(Long codeHighVuln) {
		this.codeHighVuln = codeHighVuln;
	}

	@Column(name="codemediumvuln")
	public Long getCodeMediumVuln() {
		return codeMediumVuln;
	}

	public void setCodeMediumVuln(Long codeMediumVuln) {
		this.codeMediumVuln = codeMediumVuln;
	}

	@Column(name="codelowvuln")
	public Long getCodeLowVuln() {
		return codeLowVuln;
	}

	public void setCodeLowVuln(Long codeLowVuln) {
		this.codeLowVuln = codeLowVuln;
	}

	@Column(name="scacritvuln")
	public Long getScaCritVuln() {
		return scaCritVuln;
	}

	public void setScaCritVuln(Long scaCritVuln) {
		this.scaCritVuln = scaCritVuln;
	}

	@Column(name="scahighvuln")
	public Long getScaHighVuln() {
		return scaHighVuln;
	}

	public void setScaHighVuln(Long scaHighVuln) {
		this.scaHighVuln = scaHighVuln;
	}

	@Column(name="scamediumvuln")
	public Long getScaMediumVuln() {
		return scaMediumVuln;
	}

	public void setScaMediumVuln(Long scaMediumVuln) {
		this.scaMediumVuln = scaMediumVuln;
	}

	@Column(name="scalowvuln")
	public Long getScaLowVuln() {
		return scaLowVuln;
	}

	public void setScaLowVuln(Long scaLowVuln) {
		this.scaLowVuln = scaLowVuln;
	}

	@Column(name="webappcritvuln")
	public Long getWebAppCritVuln() {
		return webAppCritVuln;
	}

	public void setWebAppCritVuln(Long webAppCritVuln) {
		this.webAppCritVuln = webAppCritVuln;
	}

	@Column(name="webapphighvuln")
	public Long getWebAppHighVuln() {
		return webAppHighVuln;
	}

	public void setWebAppHighVuln(Long webAppHighVuln) {
		this.webAppHighVuln = webAppHighVuln;
	}

	@Column(name="webappmediumvuln")
	public Long getWebAppMediumVuln() {
		return webAppMediumVuln;
	}

	public void setWebAppMediumVuln(Long webAppMediumVuln) {
		this.webAppMediumVuln = webAppMediumVuln;
	}

	@Column(name="webapplowvuln")
	public Long getWebAppLowVuln() {
		return webAppLowVuln;
	}

	public void setWebAppLowVuln(Long webAppLowVuln) {
		this.webAppLowVuln = webAppLowVuln;
	}

	@Column(name="assetcritvuln")
	public Long getAssetCritVuln() {
		return assetCritVuln;
	}

	public void setAssetCritVuln(Long assetCritVuln) {
		this.assetCritVuln = assetCritVuln;
	}

	@Column(name="assethighvuln")
	public Long getAssetHighVuln() {
		return assetHighVuln;
	}

	public void setAssetHighVuln(Long assetHighVuln) {
		this.assetHighVuln = assetHighVuln;
	}

	@Column(name="assetmediumvuln")
	public Long getAssetMediumVuln() {
		return assetMediumVuln;
	}

	public void setAssetMediumVuln(Long assetMediumVuln) {
		this.assetMediumVuln = assetMediumVuln;
	}

	@Column(name="assetlowvuln")
	public Long getAssetLowVuln() {
		return assetLowVuln;
	}

	public void setAssetLowVuln(Long assetLowVuln) {
		this.assetLowVuln = assetLowVuln;
	}
}
