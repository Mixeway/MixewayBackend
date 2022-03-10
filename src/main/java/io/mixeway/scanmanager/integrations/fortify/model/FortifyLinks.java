package io.mixeway.scanmanager.integrations.fortify.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FortifyLinks {
    FortifyLink next;
    FortifyLink last;
    FortifyLink first;
}
