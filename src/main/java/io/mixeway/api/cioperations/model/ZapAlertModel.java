package io.mixeway.api.cioperations.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
@Getter
@Setter
@NoArgsConstructor
public class ZapAlertModel {
    @JsonProperty("alert")
    private String alert;
    @JsonProperty("name")
    private String name;
    @JsonProperty("riskdesc")
    private String riskdesc;
    @JsonProperty("desc")
    private String desc;
    private List<ZapInstancesModel> instances;
    @JsonProperty("solution")
    private String solution;
    @JsonProperty("otherinfo")
    private String otherinfo;
    private String reference;


}
