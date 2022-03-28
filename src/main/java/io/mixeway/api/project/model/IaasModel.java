package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class IaasModel {
    private String iam;
    private String service;
    private String network;
    private String project;
    private boolean auto;
    private boolean enabled;
}
