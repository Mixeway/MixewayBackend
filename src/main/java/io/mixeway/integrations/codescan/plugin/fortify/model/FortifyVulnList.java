package io.mixeway.integrations.codescan.plugin.fortify.model;

import java.util.List;

public class FortifyVulnList {
    List<FortifyVuln> data;
    FortifyLinks links;

    public FortifyLinks getLinks() {
        return links;
    }

    public void setLinks(FortifyLinks links) {
        this.links = links;
    }

    public List<FortifyVuln> getData() {
        return data;
    }

    public void setData(List<FortifyVuln> data) {
        this.data = data;
    }
}
