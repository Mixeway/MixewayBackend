package io.mixeway.db.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@EntityScan
@Table(name = "scan")
@EntityListeners(AuditingEntityListener.class)
public class Scan {
    private Long id;
    private LocalDateTime inserted;
    private String triggerer;
    private String type;
    private CodeProject codeProject;
    private WebApp webapp;
    private Interface interfaceObj;
    private String branch;
    private String commitId;
    private Integer vulnCrit;
    private Integer vulnMedium;
    private Integer vulnLow;

    public Scan(String triggerer, CodeProject codeProject, String branch, String commitId, String type) {
        this.triggerer = triggerer;
        this.codeProject = codeProject;
        this.type = type;
        this.branch = branch;
        this.commitId = commitId;
        this.inserted = LocalDateTime.now();
    }

    public Scan(String triggerer, WebApp webApp, String branch, String commitId) {
        this.triggerer = triggerer;
        this.webapp = webApp;
        this.type = "DAST";
        this.branch = branch;
        this.commitId = commitId;
        this.inserted = LocalDateTime.now();
    }

    public Scan(String triggerer, Interface intf, String branch, String commitId) {
        this.triggerer = triggerer;
        this.interfaceObj = intf;
        this.type = "Network";
        this.branch = branch;
        this.commitId = commitId;
        this.inserted = LocalDateTime.now();
    }

    public Scan() {

    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    @CreationTimestamp
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    public LocalDateTime getInserted() {
        return inserted;
    }

    public void setInserted(LocalDateTime inserted) {
        this.inserted = inserted;
    }

    public String getTriggerer() {
        return triggerer;
    }

    public void setTriggerer(String triggerer) {
        this.triggerer = triggerer;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "codeproject_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
    public CodeProject getCodeProject() {
        return codeProject;
    }

    public void setCodeProject(CodeProject codeProject) {
        this.codeProject = codeProject;
    }

    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "webapp_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
    public WebApp getWebapp() {
        return webapp;
    }

    public void setWebapp(WebApp webapp) {
        this.webapp = webapp;
    }

    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "interface_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
    public Interface getInterfaceObj() {
        return interfaceObj;
    }

    public void setInterfaceObj(Interface interfaceObj) {
        this.interfaceObj = interfaceObj;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    @Column(name = "commitid")
    public String getCommitId() {
        return commitId;
    }

    public void setCommitId(String commitId) {
        this.commitId = commitId;
    }

    @Column(name = "vulncrit")
    public Integer getVulnCrit() {
        return vulnCrit;
    }

    public void setVulnCrit(Integer vulnCrit) {
        this.vulnCrit = vulnCrit;
    }

    @Column(name = "vulnmedium")
    public Integer getVulnMedium() {
        return vulnMedium;
    }

    public void setVulnMedium(Integer vulnMedium) {
        this.vulnMedium = vulnMedium;
    }

    @Column(name = "vulnlow")
    public Integer getVulnLow() {
        return vulnLow;
    }

    public void setVulnLow(Integer vulnLow) {
        this.vulnLow = vulnLow;
    }
}