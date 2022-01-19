package io.mixeway.db.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

@Entity
@EntityScan
@Table(name = "settings")
@EntityListeners(AuditingEntityListener.class)
public class Settings {
    private Long id;
    private Boolean initialized;
    private Boolean smtpAuth;
    private Boolean smtpTls;
    private String smtpHost;
    private int smtpPort;
    private String smtpUsername;
    @JsonIgnore
    private String smtpPassword;
    private Boolean passwordAuth;
    private Boolean certificateAuth;
    private Boolean keycloakAuth;
    private String masterApiKey;
    private String infraAutoCron;
    private String webAppAutoCron;
    private String codeAutoCron;
    private String trendEmailCron;
    private String domain;
    private boolean vulnAuditorEnable;
    private String vulnAuditorUrl;

    @Column(name="vulnauditorurl")
    public String getVulnAuditorUrl() {
        return vulnAuditorUrl;
    }

    public void setVulnAuditorUrl(String vulnAuditorUrl) {
        this.vulnAuditorUrl = vulnAuditorUrl;
    }

    @Column(name="vulnauditorenable")
    public boolean isVulnAuditorEnable() {
        return vulnAuditorEnable;
    }

    public void setVulnAuditorEnable(boolean vulnAuditorEnable) {
        this.vulnAuditorEnable = vulnAuditorEnable;
    }

    @Column(name="trendemailcron")
    public String getTrendEmailCron() {
        return trendEmailCron;
    }

    public void setTrendEmailCron(String trendEmailCron) {
        this.trendEmailCron = trendEmailCron;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    @Column(name = "infraautocron")
    public String getInfraAutoCron() {
        return infraAutoCron;
    }

    public void setInfraAutoCron(String infraAutoron) {
        this.infraAutoCron = infraAutoron;
    }
    @Column(name = "webappautocron")
    public String getWebAppAutoCron() {
        return webAppAutoCron;
    }

    public void setWebAppAutoCron(String webAppAutoCron) {
        this.webAppAutoCron = webAppAutoCron;
    }
    @Column(name="codeautocron")
    public String getCodeAutoCron() {
        return codeAutoCron;
    }

    public void setCodeAutoCron(String codeAutoCron) {
        this.codeAutoCron = codeAutoCron;
    }

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
