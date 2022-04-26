package io.mixeway.scanmanager.integrations.checkmarx.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CxResult {
    private String query, dstLocation, dstLine, analysis, severity, description, state;
}
