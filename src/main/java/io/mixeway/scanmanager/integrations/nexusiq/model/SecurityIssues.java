package io.mixeway.scanmanager.integrations.nexusiq.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SecurityIssues {
    private String source;
    private String reference;
    private Double severity;
    private String threatCategory;
    private String url;
}
