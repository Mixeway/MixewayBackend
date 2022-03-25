package io.mixeway.api.auth.model;


import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Setter
public class Password {
    @NotNull @Size(min = 7) String password;

}
