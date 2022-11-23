package io.mixeway.scanmanager.integrations.nexusiq.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Application {
    private String id;
    private String publicId;
    private String name;
    private String organizationId;
}
