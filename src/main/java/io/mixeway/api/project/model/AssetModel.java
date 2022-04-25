package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AssetModel {
    private Long assetId;
    private String hostname;
    private String ipAddress;
    private String routingDomain;
    private int risk;
    private boolean running;
    private boolean inQueue;
}
