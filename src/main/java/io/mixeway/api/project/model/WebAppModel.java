package io.mixeway.api.project.model;

import io.mixeway.db.entity.RoutingDomain;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class WebAppModel {
    private Long webAppId;
    private String url;
    private boolean publicScan;
    private RoutingDomain routingDomain;
    private int risk;
    private boolean running;
    private boolean inQueue;
}
