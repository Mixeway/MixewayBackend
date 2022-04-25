package io.mixeway.api.dashboard.model;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.WebApp;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class SearchResponse {
    List<Interface> assets;
    List<WebApp> webApps;
    List<CodeProject> codeProjects;
    List<VulnResponse> vulns;
}
