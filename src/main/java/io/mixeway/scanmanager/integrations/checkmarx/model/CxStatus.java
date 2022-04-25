package io.mixeway.scanmanager.integrations.checkmarx.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CxStatus {
    private long id;
    private String name;
    private String value;
}
