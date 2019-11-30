package io.mixeway.rest.project.model;

import java.util.List;

public class WebAppCard {
    List<WebAppModel> webAppModels;
    boolean webAppAutoScan;

    public List<WebAppModel> getWebAppModels() {
        return webAppModels;
    }

    public void setWebAppModels(List<WebAppModel> webAppModels) {
        this.webAppModels = webAppModels;
    }

    public boolean isWebAppAutoScan() {
        return webAppAutoScan;
    }

    public void setWebAppAutoScan(boolean webAppAutoScan) {
        this.webAppAutoScan = webAppAutoScan;
    }
}
