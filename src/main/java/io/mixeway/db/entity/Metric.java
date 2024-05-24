package io.mixeway.db.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

@Entity
@EntityScan
@Table(name = "metric")
@EntityListeners(AuditingEntityListener.class)
@JsonIgnoreProperties(ignoreUnknown=true)
public class Metric {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "activevulnavg")
    private int activeVulnAvg;

    @Column(name = "activevulnno")
    private int activeVulnNo;

    @Column(name = "fixedvulnno")
    private int fixedVulnNo;

    @Column(name = "fixedvulnpercent")
    private int fixedVulnPercent;

    @Column(name = "fixtime")
    private int fixTime;

    @Column(name = "projectwithcicdno")
    private int projectWithCicdNo;

    @Column(name = "projectwithcicdpercent")
    private int projectWithCicdPercent;

    @Column(name = "securejobno")
    private int secureJobNo;

    @Column(name = "securejobpercent")
    private int secureJobPercent;

    @Column(name = "bugtrackingintegratedno")
    private int bugTrackingIntegratedNo;

    @Column(name = "bugtrackingintegratedpercent")
    private int bugTrackingIntegratedPercent;

    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "project_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private Project project;

    public Metric() {
    }

    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public int getActiveVulnAvg() {
        return activeVulnAvg;
    }

    public void setActiveVulnAvg(int activeVulnAvg) {
        this.activeVulnAvg = activeVulnAvg;
    }

    public int getActiveVulnNo() {
        return activeVulnNo;
    }

    public void setActiveVulnNo(int activeVulnNo) {
        this.activeVulnNo = activeVulnNo;
    }

    public int getFixedVulnNo() {
        return fixedVulnNo;
    }

    public void setFixedVulnNo(int fixedVulnNo) {
        this.fixedVulnNo = fixedVulnNo;
    }

    public int getFixedVulnPercent() {
        return fixedVulnPercent;
    }

    public void setFixedVulnPercent(int fixedVulnPercent) {
        this.fixedVulnPercent = fixedVulnPercent;
    }

    public int getFixTime() {
        return fixTime;
    }

    public void setFixTime(int fixTime) {
        this.fixTime = fixTime;
    }

    public int getProjectWithCicdNo() {
        return projectWithCicdNo;
    }

    public void setProjectWithCicdNo(int projectWithCicdNo) {
        this.projectWithCicdNo = projectWithCicdNo;
    }

    public int getProjectWithCicdPercent() {
        return projectWithCicdPercent;
    }

    public void setProjectWithCicdPercent(int projectWithCicdPercent) {
        this.projectWithCicdPercent = projectWithCicdPercent;
    }

    public int getSecureJobNo() {
        return secureJobNo;
    }

    public void setSecureJobNo(int secureJobNo) {
        this.secureJobNo = secureJobNo;
    }

    public int getSecureJobPercent() {
        return secureJobPercent;
    }

    public void setSecureJobPercent(int secureJobPercent) {
        this.secureJobPercent = secureJobPercent;
    }

    public int getBugTrackingIntegratedNo() {
        return bugTrackingIntegratedNo;
    }

    public void setBugTrackingIntegratedNo(int bugTrackingIntegratedNo) {
        this.bugTrackingIntegratedNo = bugTrackingIntegratedNo;
    }

    public int getBugTrackingIntegratedPercent() {
        return bugTrackingIntegratedPercent;
    }

    public void setBugTrackingIntegratedPercent(int bugTrackingIntegratedPercent) {
        this.bugTrackingIntegratedPercent = bugTrackingIntegratedPercent;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }
}