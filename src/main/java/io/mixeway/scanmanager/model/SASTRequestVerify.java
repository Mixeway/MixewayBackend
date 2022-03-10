package io.mixeway.scanmanager.model;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SASTRequestVerify {
    private Boolean valid;
    private CodeGroup cg;
    private CodeProject cp;
}
