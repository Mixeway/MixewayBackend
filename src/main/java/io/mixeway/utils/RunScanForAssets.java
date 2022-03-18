package io.mixeway.utils;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RunScanForAssets {
    Long assetId;
    String hostname;
    String ipAddress;
    String routingDomain;
    int risk;
    boolean running;

}
