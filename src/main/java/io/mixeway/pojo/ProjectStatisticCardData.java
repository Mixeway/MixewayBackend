package io.mixeway.pojo;

public class ProjectStatisticCardData {
    String id;
    String cardTitle;
    String cardDescription;
    ShowProjectVulnSummary2 showProjectVulnSummary;
    ProjectStatisticChartData chartName;
    ProjectStatisticChartData chartVuln;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCardTitle() {
        return cardTitle;
    }

    public void setCardTitle(String cardTitle) {
        this.cardTitle = cardTitle;
    }

    public String getCardDescription() {
        return cardDescription;
    }

    public void setCardDescription(String cardDescription) {
        this.cardDescription = cardDescription;
    }

    public ShowProjectVulnSummary2 getShowProjectVulnSummary() {
        return showProjectVulnSummary;
    }

    public void setShowProjectVulnSummary(ShowProjectVulnSummary2 showProjectVulnSummary) {
        this.showProjectVulnSummary = showProjectVulnSummary;
    }

    public ProjectStatisticChartData getChartName() {
        return chartName;
    }

    public void setChartName(ProjectStatisticChartData chartName) {
        this.chartName = chartName;
    }

    public ProjectStatisticChartData getChartVuln() {
        return chartVuln;
    }

    public void setChartVuln(ProjectStatisticChartData chartVuln) {
        this.chartVuln = chartVuln;
    }
}
