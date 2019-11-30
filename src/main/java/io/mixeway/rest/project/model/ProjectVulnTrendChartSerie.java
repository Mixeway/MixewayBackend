package io.mixeway.rest.project.model;

import java.util.LinkedList;

public class ProjectVulnTrendChartSerie {
    String name;
    LinkedList<Integer> values;

    public LinkedList<Integer> getValues() {
        return values;
    }

    public void setValues(LinkedList<Integer> values) {
        this.values = values;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
