package io.mixeway.api.cicd.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class GitleaksReport {
    ProjectMetadata projectMetadata;
    List<GitleaksReportEntry> findings;

}
