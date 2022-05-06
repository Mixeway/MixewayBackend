package io.mixeway.api.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class StatusEntity {
    Boolean initialized;
    Boolean password;
    Boolean cert;
    Boolean facebook;
    Boolean gitHub;
    Boolean keycloak;
}
