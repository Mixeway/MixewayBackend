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
@Table(name = "assethistory")
@EntityListeners(AuditingEntityListener.class)
public class AssetHistory {
    private Long id;
    private LocalDateTime inserted;
    private CodeProject codeProject;
    private WebApp webapp;
    private Interface interfaceObj;
    private Integer scaVulns;
    private Integer sastVulns;
    private Integer iacVulns;
    private Integer secretVulns;
    private Integer dastVulns;
    private Integer networkVulns;
    private Integer crit;
    private Integer high;
    private Integer medium;
    private Integer low;

    public AssetHistory() {
    }
    public AssetHistory(Scannable scannable, int scaVulns, int sastVulns, int iacVulns, int secretVulns, int dastVulns, int networkVulns,
                        int crit, int high, int medium, int low){
        if (scannable instanceof CodeProject) {
            this.codeProject = (CodeProject) scannable;
        } else if (scannable instanceof WebApp) {
            this.webapp = (WebApp) scannable;
        } else if (scannable instanceof Interface) {
            this.interfaceObj = (Interface) scannable;
        }
        this.sastVulns = sastVulns;
        this.iacVulns = iacVulns;
        this.secretVulns = secretVulns;
        this.dastVulns = dastVulns;
        this.networkVulns = networkVulns;
        this.scaVulns = scaVulns;
        this.crit = crit;
        this.high = high;
        this.medium = medium;
        this.low = low;
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

    @Column(name = "scavulns")
    public Integer getScaVulns() {
        return scaVulns;
    }

    public void setScaVulns(Integer scaVulns) {
        this.scaVulns = scaVulns;
    }

    @Column(name = "sastvulns")
    public Integer getSastVulns() {
        return sastVulns;
    }

    public void setSastVulns(Integer sastVulns) {
        this.sastVulns = sastVulns;
    }

    @Column(name = "iacvulns")
    public Integer getIacVulns() {
        return iacVulns;
    }

    public void setIacVulns(Integer iacVulns) {
        this.iacVulns = iacVulns;
    }

    @Column(name = "secretvulns")
    public Integer getSecretVulns() {
        return secretVulns;
    }

    public void setSecretVulns(Integer secretVulns) {
        this.secretVulns = secretVulns;
    }

    @Column(name = "dastvulns")
    public Integer getDastVulns() {
        return dastVulns;
    }

    public void setDastVulns(Integer dastVulns) {
        this.dastVulns = dastVulns;
    }

    @Column(name = "networkvulns")
    public Integer getNetworkVulns() {
        return networkVulns;
    }

    public void setNetworkVulns(Integer networkVulns) {
        this.networkVulns = networkVulns;
    }

    public Integer getCrit() {
        return crit;
    }

    public void setCrit(Integer crit) {
        this.crit = crit;
    }

    public Integer getHigh() {
        return high;
    }

    public void setHigh(Integer high) {
        this.high = high;
    }

    public Integer getMedium() {
        return medium;
    }

    public void setMedium(Integer medium) {
        this.medium = medium;
    }

    public Integer getLow() {
        return low;
    }

    public void setLow(Integer low) {
        this.low = low;
    }
}