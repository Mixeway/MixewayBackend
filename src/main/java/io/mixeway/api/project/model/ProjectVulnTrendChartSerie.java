package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

import java.util.LinkedList;

@Getter
@Setter
public class ProjectVulnTrendChartSerie {
    private String name;
    private LinkedList<Integer> values;

}
