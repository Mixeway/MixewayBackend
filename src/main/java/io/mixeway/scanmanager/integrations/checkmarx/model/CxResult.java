package io.mixeway.scanmanager.integrations.checkmarx.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CxResult {
    private String query, dstLocation, dstLine, analysis, severity, description, state;
}
