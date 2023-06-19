package io.mixeway.api.cioperations.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
public class ZapSiteModel {
    @JsonProperty ("@name")
    private String name;
    private List<ZapAlertModel> alerts;


}
