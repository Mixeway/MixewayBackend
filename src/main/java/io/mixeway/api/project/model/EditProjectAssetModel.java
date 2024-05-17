package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class EditProjectAssetModel {
    private Long id;
    private String type;
    private String name;
    private String target;
    private String branch;
}
