package io.mixeway.api.admin.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthSettingsModel {
    Boolean passwordAuth;
    Boolean certificateAuth;
}
