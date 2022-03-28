package io.mixeway.api.dashboard.model;

/**
 * @author gsiewruk
 */
public class StatisticCard {
    Long projects;
    Long scanRunning;
    Long scanInQueue;
    Long vulnerabilities;

    public StatisticCard(Long projects, Long scanRunning, Long scanInQueue, Long vulnerabilities) {
        this.projects = projects;
        this.scanInQueue = scanInQueue;
        this.scanRunning = scanRunning;
        this.vulnerabilities = vulnerabilities;
    }

    public Long getProjects() {
        return projects;
    }

    public void setProjects(Long projects) {
        this.projects = projects;
    }

    public Long getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(Long vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public Long getScanRunning() {
        return scanRunning;
    }

    public void setScanRunning(Long scanRunning) {
        this.scanRunning = scanRunning;
    }

    public Long getScanInQueue() {
        return scanInQueue;
    }

    public void setScanInQueue(Long scanInQueue) {
        this.scanInQueue = scanInQueue;
    }
}
