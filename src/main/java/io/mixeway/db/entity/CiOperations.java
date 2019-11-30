package io.mixeway.db.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.util.Date;

@Entity
@EntityScan
@Table(name = "cioperations")
@EntityListeners(AuditingEntityListener.class)
public class CiOperations {
    Long id;
    Project project;
    CodeGroup codeGroup;
    CodeProject codeProject;
    Date inserted;
    String result;
    int vulnNumber;

    @Column(name = "vulnnumber")
    public int getVulnNumber() {
        return vulnNumber;
    }

    public void setVulnNumber(int vulnNumber) {
        this.vulnNumber = vulnNumber;
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
    @JoinColumn(name = "project_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }
    @ManyToOne(fetch = FetchType.EAGER, optional = true)
    @JoinColumn(name = "codegroup_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    public CodeGroup getCodeGroup() {
        return codeGroup;
    }

    public void setCodeGroup(CodeGroup codeGroup) {
        this.codeGroup = codeGroup;
    }

    @ManyToOne(fetch = FetchType.EAGER, optional = true)
    @JoinColumn(name = "codeproject_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    public CodeProject getCodeProject() {
        return codeProject;
    }

    public void setCodeProject(CodeProject codeProject) {
        this.codeProject = codeProject;
    }
    @CreationTimestamp
    @Temporal(TemporalType.TIMESTAMP)
    public Date getInserted() {
        return inserted;
    }

    public void setInserted(Date inserted) {
        this.inserted = inserted;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }
}
