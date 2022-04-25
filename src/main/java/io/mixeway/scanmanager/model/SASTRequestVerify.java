package io.mixeway.scanmanager.model;

import io.mixeway.db.entity.CodeProject;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@Builder
public class SASTRequestVerify {
    private Boolean valid;
    private CodeProject cp;
}
