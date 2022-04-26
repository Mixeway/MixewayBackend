package io.mixeway.scanmanager.integrations.checkmarx.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CxStatus {
    private long id;
    private String name;
    private String value;
}
