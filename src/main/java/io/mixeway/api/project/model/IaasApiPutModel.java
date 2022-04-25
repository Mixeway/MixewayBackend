package io.mixeway.api.project.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class IaasApiPutModel {

    private String iamApi;
    private String networkApi;
    private String serviceApi;
    private String projectid;
    private String username;
    private String password;
    @NotBlank private String apiType;
    private String region;

    @NotNull
    @Min(1) private Long routingDomainForIaasApi;

}
