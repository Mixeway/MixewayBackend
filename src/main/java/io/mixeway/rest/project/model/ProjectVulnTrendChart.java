package io.mixeway.rest.project.model;

import java.util.LinkedList;
import java.util.List;

public class ProjectVulnTrendChart {
    List<ProjectVulnTrendChartSerie>series;
    LinkedList<String> legends;
    LinkedList<String> dates;

    public LinkedList<String> getLegends() {
        return legends;
    }

    public void setLegends(LinkedList<String> legends) {
        this.legends = legends;
    }

    public LinkedList<String> getDates() {
        return dates;
    }

    public void setDates(LinkedList<String> dates) {
        this.dates = dates;
    }

    public List<ProjectVulnTrendChartSerie> getSeries() {
        return series;
    }

    public void setSeries(List<ProjectVulnTrendChartSerie> series) {
        this.series = series;
    }
}
