package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class AssetVulns {
    int critical;
    int medium;
    int low;
}
