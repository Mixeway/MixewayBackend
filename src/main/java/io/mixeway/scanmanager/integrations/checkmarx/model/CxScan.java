package io.mixeway.scanmanager.integrations.checkmarx.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CxScan {
    private long id;
    private CxProject project;
    private CxStatus status;
}
