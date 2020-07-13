package io.mixeway.db.entity;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

/**
 * @author gsiewruk
 */
@Entity
@EntityScan
@Table(name = "securitygatway")
@EntityListeners(AuditingEntityListener.class)
public class SecurityGateway {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private boolean grade;
    private int vuln;
    private int high;
    private int critical;
    private int medium;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public boolean isGrade() {
        return grade;
    }

    public void setGrade(boolean grade) {
        this.grade = grade;
    }

    public int getVuln() {
        return vuln;
    }

    public void setVuln(int vuln) {
        this.vuln = vuln;
    }

    public int getHigh() {
        return high;
    }

    public void setHigh(int high) {
        this.high = high;
    }

    public int getCritical() {
        return critical;
    }

    public void setCritical(int critical) {
        this.critical = critical;
    }

    public int getMedium() {
        return medium;
    }

    public void setMedium(int medium) {
        this.medium = medium;
    }
}
