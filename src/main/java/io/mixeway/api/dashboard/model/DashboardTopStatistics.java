package io.mixeway.api.dashboard.model;

import io.mixeway.db.entity.ProjectVulnerability;

import java.util.List;

/**
 * @author gsiewruk
 */
public class DashboardTopStatistics {
    List<ProjectVulnerability> projectVulnerabilityList;
    StatisticCard statisticCard;

    public DashboardTopStatistics(List<ProjectVulnerability> projectVulnerabilityList, StatisticCard statisticCard) {
        this.projectVulnerabilityList = projectVulnerabilityList;
        this.statisticCard = statisticCard;
    }

    public DashboardTopStatistics() {
    }

    public List<ProjectVulnerability> getProjectVulnerabilityList() {
        return projectVulnerabilityList;
    }

    public void setProjectVulnerabilityList(List<ProjectVulnerability> projectVulnerabilityList) {
        this.projectVulnerabilityList = projectVulnerabilityList;
    }

    public StatisticCard getStatisticCard() {
        return statisticCard;
    }

    public void setStatisticCard(StatisticCard statisticCard) {
        this.statisticCard = statisticCard;
    }
}
