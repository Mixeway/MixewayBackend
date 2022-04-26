package io.mixeway.scanmanager.integrations.checkmarx.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CxLoginResponse {
    private String access_token;
    private long expires_in;
    private String token_type;

}
