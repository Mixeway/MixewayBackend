package io.mixeway.api.cicd.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class KicsReport {
    ProjectMetadata projectMetadata;
    KicsReportEntry findings;


}
