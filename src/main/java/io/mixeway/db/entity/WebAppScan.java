package io.mixeway.db.entity;

import javax.persistence.*;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.text.SimpleDateFormat;
import java.util.Date;

@Entity
@EntityScan
@Table(name = "webappscan")
@EntityListeners(AuditingEntityListener.class)
public class WebAppScan {
	private Long id;
	private Project project;
	private Scanner scanner;
	private Boolean running;
	private String scanId;
	private String type;
	private WebApp webApp;
	private String inserted;
	private String updated;

	public WebAppScan(WebApp webApp){
		this.webApp = webApp;
	}

	@Column(name = "inserted")
	public String getInserted() {
		return inserted;
	}

	public void setInserted(String inserted) {
		this.inserted = inserted;
	}

	@Column(name = "updated")
	public String getUpdated() {
		return updated;
	}

	public void setUpdated(String updated) {
		this.updated = updated;
	}

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	
	@ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "nessus_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public Scanner getScanner() {
		return scanner;
	}
	public void setScanner(Scanner scanner) {
		this.scanner = scanner;
	}
	public Boolean getRunning() {
		return running;
	}
	public void setRunning(Boolean running) {
		this.running = running;
	}
	@Column(name="scan_id")
	public String getScanId() {
		return scanId;
	}
	public void setScanId(String scanId) {
		this.scanId = scanId;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	@ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "webapp_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public WebApp getWebApp() {
		return webApp;
	}
	public void setWebApp(WebApp webApp) {
		this.webApp = webApp;
	}
	@ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "project_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
	public Project getProject() {
		return project;
	}
	public void setProject(Project project) {
		this.project = project;
	}

	@PrePersist
	public void setInsertedDate() {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		this.inserted = sdf.format(new Date());
	}
	@PreUpdate
	public void setUpdatedDate() {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		this.updated = sdf.format(new Date());
	}


}
