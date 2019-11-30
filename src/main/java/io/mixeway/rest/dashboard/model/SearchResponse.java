package io.mixeway.rest.dashboard.model;

import io.mixeway.db.entity.Interface;
import io.mixeway.rest.model.VulnResponse;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.WebApp;

import java.util.List;

public class SearchResponse {
    List<Interface> assets;
    List<WebApp> webApps;
    List<CodeProject> codeProjects;
    List<VulnResponse> vulns;

    public List<Interface> getAssets() {
        return assets;
    }

    public void setAssets(List<Interface> assets) {
        this.assets = assets;
    }

    public List<WebApp> getWebApps() {
        return webApps;
    }

    public void setWebApps(List<WebApp> webApps) {
        this.webApps = webApps;
    }

    public List<CodeProject> getCodeProjects() {
        return codeProjects;
    }

    public void setCodeProjects(List<CodeProject> codeProjects) {
        this.codeProjects = codeProjects;
    }

    public List<VulnResponse> getVulns() {
        return vulns;
    }

    public void setVulns(List<VulnResponse> vulns) {
        this.vulns = vulns;
    }
}
