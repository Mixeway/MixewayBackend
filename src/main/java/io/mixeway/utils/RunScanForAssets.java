package io.mixeway.utils;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class RunScanForAssets {
    Long assetId;
    String hostname;
    String ipAddress;
    String routingDomain;
    int risk;
    boolean running;

}
