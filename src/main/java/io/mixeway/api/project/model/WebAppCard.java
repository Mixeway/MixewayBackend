package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class WebAppCard {
    private List<WebAppModel> webAppModels;
    private boolean webAppAutoScan;
}
