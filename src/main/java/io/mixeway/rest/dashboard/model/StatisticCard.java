package io.mixeway.rest.dashboard.model;

/**
 * @author gsiewruk
 */
public class StatisticCard {
    Long projects;
    Long assets;
    Long webApps;
    Long repos;
    Long vulnerabilities;

    public StatisticCard(Long projects, Long assets, Long webApps, Long repos, Long vulnerabilities) {
        this.projects = projects;
        this.assets = assets;
        this.webApps = webApps;
        this.repos = repos;
        this.vulnerabilities = vulnerabilities;
    }

    public Long getProjects() {
        return projects;
    }

    public void setProjects(Long projects) {
        this.projects = projects;
    }

    public Long getAssets() {
        return assets;
    }

    public void setAssets(Long assets) {
        this.assets = assets;
    }

    public Long getWebApps() {
        return webApps;
    }

    public void setWebApps(Long webApps) {
        this.webApps = webApps;
    }

    public Long getRepos() {
        return repos;
    }

    public void setRepos(Long repos) {
        this.repos = repos;
    }

    public Long getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(Long vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }
}
