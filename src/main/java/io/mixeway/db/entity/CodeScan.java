package io.mixeway.db.entity;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.text.SimpleDateFormat;
import java.util.Date;

@Entity
@EntityScan
@Table(name = "codescan")
@EntityListeners(AuditingEntityListener.class)
public class CodeScan {
    private Long id;
    private CodeProject codeProject;
    private String inserted;
    private boolean inQueue;
    private boolean running;
    private String updated;

    public CodeScan(CodeProject codeProject){
        this.codeProject = codeProject;
    }
    @Column(name = "updated")
    public String getUpdated() {
        return updated;
    }

    public void setUpdated(String updated) {
        this.updated = updated;
    }

    public boolean isRunning() {
        return running;
    }

    public void setRunning(boolean running) {
        this.running = running;
    }
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "codeproject_id", nullable = false)
    public CodeProject getCodeProject() {
        return codeProject;
    }

    public void setCodeProject(CodeProject codeProject) {
        this.codeProject = codeProject;
    }

    public String getInserted() {
        return inserted;
    }

    public void setInserted(String inserted) {
        this.inserted = inserted;
    }

    public boolean isInQueue() {
        return inQueue;
    }

    public void setInQueue(boolean inQueue) {
        this.inQueue = inQueue;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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
