package io.mixeway.scanmanager.integrations.nexusiq.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.Security;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ReportEntry {
    private String packageUrl;
    private String displayName;
    private ComponentIdentifier componentIdentifier;
    private SecurityData securityData;
}
