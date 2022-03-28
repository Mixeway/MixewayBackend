package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class AssetCard {
    private List<AssetModel> assets;
    private boolean autoInfraScan;
}
