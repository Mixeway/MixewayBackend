package io.mixeway.scanmanager.integrations.checkmarx.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CxLoginResponse {
    private String access_token;
    private long expires_in;
    private String token_type;

}
