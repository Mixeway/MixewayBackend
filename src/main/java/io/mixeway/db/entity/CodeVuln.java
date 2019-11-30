package io.mixeway.db.entity;

import javax.persistence.*;

import io.mixeway.pojo.Vulnerability;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@EntityScan
@Table(name = "codevuln")
@EntityListeners(AuditingEntityListener.class)
@Cacheable
@org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
public class CodeVuln implements Vulnerability {
	private Long id;
	private CodeProject codeProject;
	private CodeGroup codeGroup;
	private String name;
	private String filePath;
	private String severity;
	private String analysis;
	private String inserted;
	private String description;
	private Status status;
	private String ticketId;
	private Long externalId;

	@Column(name="externalid")
	public Long getExternalId() {
		return externalId;
	}

	public void setExternalId(Long externalId) {
		this.externalId = externalId;
	}

	@Column(name="ticketid")
	public String getTicketId() {
		return ticketId;
	}

	public void setTicketId(String ticketId) {
		this.ticketId = ticketId;
	}

	@ManyToOne(fetch = FetchType.EAGER, optional = true)
	@JoinColumn(name = "status_id", nullable = true)
	@OnDelete(action = OnDeleteAction.CASCADE)
	public Status getStatus() {
		return status;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public String getInserted() {
		return inserted;
	}
	public void setInserted(String inserted) {
		this.inserted = inserted;
	}
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	@ManyToOne(fetch = FetchType.EAGER, optional = false, cascade = CascadeType.MERGE)
    @JoinColumn(name = "codeproject_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public CodeProject getCodeProject() {
		return codeProject;
	}
	public void setCodeProject(CodeProject codeProject) {
		this.codeProject = codeProject;
	}
	@ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "codegroup_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
	public CodeGroup getCodeGroup() {
		return codeGroup;
	}
	public void setCodeGroup(CodeGroup codeGroup) {
		this.codeGroup = codeGroup;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	@Column(name="filepath")
	public String getFilePath() {
		return filePath;
	}
	public void setFilePath(String filePath) {
		this.filePath = filePath;
	}
	public String getSeverity() {
		return severity;
	}
	public void setSeverity(String severity) {
		this.severity = severity;
	}
	public String getAnalysis() {
		return analysis;
	}
	public void setAnalysis(String analysis) {
		this.analysis = analysis;
	}
	
	
	

}
