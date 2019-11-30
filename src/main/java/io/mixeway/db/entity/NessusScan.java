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
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@EntityScan
@Table(name = "nessusscan")
@EntityListeners(AuditingEntityListener.class)
public class NessusScan {
	
	private Long id;
	private Project project;
	private NessusScanner nessusScanner;
	private NessusScanTemplate nessusScanTemplate;
	private Scanner nessus;
	private int scanId;
	private Boolean running;
	private Boolean scheduled;
	private Boolean publicip;
	private String lastExecuted;
	private Set<Interface> interfaces;
	private Boolean isAutomatic;
	private int scanFrequency;
	private String reportId;
	private String taskId;
	private String targetId;
	private String requestId;

	@Column(name="requestid")
	public String getRequestId() {
		return requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
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
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "nessusscanner_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public NessusScanner getNessusScanner() {
		return nessusScanner;
	}
	public void setNessusScanner(NessusScanner nessusScanner) {
		this.nessusScanner = nessusScanner;
	}
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "nessusscantemplate_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public NessusScanTemplate getNessusScanTemplate() {
		return nessusScanTemplate;
	}
	public void setNessusScanTemplate(NessusScanTemplate nessusScanTemplate) {
		this.nessusScanTemplate = nessusScanTemplate;
	}
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "nessus_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public Scanner getNessus() {
		return nessus;
	}
	public void setNessus(Scanner nessus) {
		this.nessus = nessus;
	}
	@Column(name="scanid")
	public int getScanId() {
		return scanId;
	}
	public void setScanId(int scanId) {
		this.scanId = scanId;
	}
	public Boolean getRunning() {
		return running;
	}
	public void setRunning(Boolean running) {
		this.running = running;
	}
	public Boolean getScheduled() {
		return scheduled;
	}
	public void setScheduled(Boolean scheduled) {
		this.scheduled = scheduled;
	}
	public Boolean getPublicip() {
		return publicip;
	}
	public void setPublicip(Boolean publicip) {
		this.publicip = publicip;
	}
	@Column(name="lastexecuted")
	public String getLastExecuted() {
		return lastExecuted;
	}
	public void setLastExecuted(String lastExecuted) {
		this.lastExecuted = lastExecuted;
	}
	@ManyToMany(fetch = FetchType.LAZY,cascade = {CascadeType.PERSIST,CascadeType.MERGE,CascadeType.DETACH})
	@JoinTable(name = "nessus_interface", joinColumns = {@JoinColumn(name="nessusscan_id", referencedColumnName="id")}, 
				inverseJoinColumns= {@JoinColumn(name="interface_id", referencedColumnName="id")})
	public Set<Interface> getInterfaces() {
		return interfaces;
	}
	public void setInterfaces(Set<Interface> interfaces) {
		this.interfaces = interfaces;
	}
	@Column(name="isautomatic")
	public Boolean getIsAutomatic() {
		return isAutomatic;
	}
	public void setIsAutomatic(Boolean isAutomatic) {
		this.isAutomatic = isAutomatic;
	}
	@Column(name="scanfrequency")
	public int getScanFrequency() {
		return scanFrequency;
	}
	public void setScanFrequency(int scanFrequency) {
		this.scanFrequency = scanFrequency;
	}
	@Column(name="reportid")
	public String getReportId() {
		return reportId;
	}
	public void setReportId(String reportId) {
		this.reportId = reportId;
	}
	@Column(name="taskid")
	public String getTaskId() {
		return taskId;
	}
	public void setTaskId(String taskId) {
		this.taskId = taskId;
	}
	@Column(name="targetid")
	public String getTargetId() {
		return targetId;
	}
	public void setTargetId(String targetId) {
		this.targetId = targetId;
	}
	
	
	

}
