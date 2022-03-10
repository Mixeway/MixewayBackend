package io.mixeway.utils;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Setter
@Getter
public class ScannerModel {
    private String scannerType;
    private Long routingDomain;
    private Long proxy;
    private String apiUrl;
    private String username;
    private String password;
    private String secretkey;
    private String accesskey;
    private String apiKey;
    private String cloudCtrlToken;
}
