package io.mixeway.rest.project.model;

import java.util.List;

public class AssetCard {
    List<AssetModel> assets;
    boolean autoInfraScan;

    public List<AssetModel> getAssets() {
        return assets;
    }

    public void setAssets(List<AssetModel> assets) {
        this.assets = assets;
    }

    public boolean isAutoInfraScan() {
        return autoInfraScan;
    }

    public void setAutoInfraScan(boolean autoInfraScan) {
        this.autoInfraScan = autoInfraScan;
    }
}
