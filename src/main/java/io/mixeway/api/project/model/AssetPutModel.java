package io.mixeway.api.project.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AssetPutModel {
    @NotEmpty private String assetName;
    @NotEmpty
    private String ipAddresses;
    @NotNull
    @Min(1) private Long routingDomainForAsset;

}
