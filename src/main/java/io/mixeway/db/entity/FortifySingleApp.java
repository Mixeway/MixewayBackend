package io.mixeway.db.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

@Entity
@EntityScan
@Table(name = "fortifysingleapp")
@EntityListeners(AuditingEntityListener.class)
public class FortifySingleApp {
    private Long id;
    private String requestId;
    private String jobToken;
    private CodeProject codeProject;
    private Boolean finished;
    private Boolean downloaded;

    public Boolean getDownloaded() {
        return downloaded;
    }

    public void setDownloaded(Boolean downloaded) {
        this.downloaded = downloaded;
    }

    @Column(name = "jobtoken")
    public String getJobToken() {
        return jobToken;
    }

    public void setJobToken(String jobToken) {
        this.jobToken = jobToken;
    }

    public Boolean getFinished() {
        return finished;
    }

    public void setFinished(Boolean finished) {
        this.finished = finished;
    }
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }
    @Column(name = "requestid")
    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "codeproject_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
    public CodeProject getCodeProject() {
        return codeProject;
    }

    public void setCodeProject(CodeProject codeProject) {
        this.codeProject = codeProject;
    }
}
