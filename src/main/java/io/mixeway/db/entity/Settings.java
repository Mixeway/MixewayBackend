package io.mixeway.db.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

@Entity
@EntityScan
@Table(name = "settings")
@EntityListeners(AuditingEntityListener.class)
public class Settings {
    Long id;
    Boolean initialized;
    Boolean smtpAuth;
    Boolean smtpTls;
    String smtpHost;
    int smtpPort;
    String smtpUsername;
    @JsonIgnore String smtpPassword;
    Boolean passwordAuth;
    Boolean certificateAuth;
    String masterApiKey;

    @Column(name="masterapikey")
    public String getMasterApiKey() {
        return masterApiKey;
    }

    public void setMasterApiKey(String masterApiKey) {
        this.masterApiKey = masterApiKey;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Boolean getInitialized() {
        return initialized;
    }

    public void setInitialized(Boolean initialized) {
        this.initialized = initialized;
    }


    @Column(name="smtpauth")
    public Boolean getSmtpAuth() {
        return smtpAuth;
    }
    public void setSmtpAuth(Boolean smtpAuth) {
        this.smtpAuth = smtpAuth;
    }

    @Column(name="smtptls")
    public Boolean getSmtpTls() {
        return smtpTls;
    }

    public void setSmtpTls(Boolean smtpTls) {
        this.smtpTls = smtpTls;
    }

    @Column(name="smtphost")
    public String getSmtpHost() {
        return smtpHost;
    }

    public void setSmtpHost(String smtpHost) {
        this.smtpHost = smtpHost;
    }

    @Column(name="smtpport")
    public int getSmtpPort() {
        return smtpPort;
    }

    public void setSmtpPort(int smtpPort) {
        this.smtpPort = smtpPort;
    }

    @Column(name="smtpusername")
    public String getSmtpUsername() {
        return smtpUsername;
    }

    public void setSmtpUsername(String smtpUsername) {
        this.smtpUsername = smtpUsername;
    }

    @Column(name="smtppassword")
    public String getSmtpPassword() {
        return smtpPassword;
    }

    public void setSmtpPassword(String smtpPassword) {
        this.smtpPassword = smtpPassword;
    }

    @Column(name="passwordauth")
    public Boolean getPasswordAuth() {
        return passwordAuth;
    }

    public void setPasswordAuth(Boolean passwordAuth) {
        this.passwordAuth = passwordAuth;
    }

    @Column(name="certificateauth")
    public Boolean getCertificateAuth() {
        return certificateAuth;
    }

    public void setCertificateAuth(Boolean certificateAuth) {
        this.certificateAuth = certificateAuth;
    }
}
