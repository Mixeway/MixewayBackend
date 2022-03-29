package io.mixeway.api.vulnmanage.model;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Pattern;

@Getter
@Setter
public class RequestId {
    @Pattern(regexp = "[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}",message = "UUID format required")
    private String requestId;

    @Override
    public String toString(){
        return this.requestId;
    }
}
