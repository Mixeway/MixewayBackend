package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

import java.util.LinkedList;
import java.util.List;

@Getter
@Setter
public class ProjectVulnTrendChart {
    private List<ProjectVulnTrendChartSerie>series;
    private LinkedList<String> legends;
    private LinkedList<String> dates;

}
