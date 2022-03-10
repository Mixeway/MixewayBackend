package io.mixeway.scanmanager.integrations.fortify.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class FortifyProjectVersionDto {
    @JsonProperty("data")
    private List<FortifyProjectVersions> fortifyProjectVersions;

}
