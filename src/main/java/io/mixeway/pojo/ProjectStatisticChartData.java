package io.mixeway.pojo;

import java.util.List;

public class ProjectStatisticChartData {
    List<BarChartProjection> projections;
    String id;
    String title;
    String label;

    public List<BarChartProjection> getProjections() {
        return projections;
    }

    public void setProjections(List<BarChartProjection> projections) {
        this.projections = projections;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }
}
