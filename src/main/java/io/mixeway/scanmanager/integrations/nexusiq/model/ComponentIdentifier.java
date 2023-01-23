package io.mixeway.scanmanager.integrations.nexusiq.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ComponentIdentifier {
    private String format;
    private Coordinates coordinates;
}
