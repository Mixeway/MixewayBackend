package io.mixeway.api.cicd.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ScanRequestModel {
    String type;
    String repoUrl;
    String branch;
    String commitid;
}
