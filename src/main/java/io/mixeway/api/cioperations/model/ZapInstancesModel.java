package io.mixeway.api.cioperations.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ZapInstancesModel {
    @JsonProperty("uri")
    private String uri;
    @JsonProperty("method")
    private String method;
    @JsonProperty("param")
    private String param;
    @JsonProperty("attack")
    private String attack;
    @JsonProperty("evidence")
    private String evidence;
    @JsonProperty("otherinfo")
    private String otherinfo;
}
