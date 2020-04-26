package io.mixeway.rest.model;

public class Projects {
    Long id;
    String name;
    String description;
    int risk;
    String ciid;
    int enableVulnManage;

    public int getEnableVulnManage() {
        return enableVulnManage;
    }

    public void setEnableVulnManage(int enableVulnManage) {
        this.enableVulnManage = enableVulnManage;
    }

    public String getCiid() {
        return ciid;
    }

    public void setCiid(String ciid) {
        this.ciid = ciid;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public int getRisk() {
        return risk;
    }

    public void setRisk(int risk) {
        this.risk = risk;
    }
}
