package io.mixeway.integrations.codescan.plugin.fortify.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class FortifyProjectVersionDto {
    @JsonProperty("data")
    private List<FortifyProjectVersions> fortifyProjectVersions;

    public List<FortifyProjectVersions> getFortifyProjectVersions() {
        return fortifyProjectVersions;
    }

    public void setFortifyProjectVersions(List<FortifyProjectVersions> fortifyProjectVersions) {
        this.fortifyProjectVersions = fortifyProjectVersions;
    }
}
