package io.mixeway.rest.project.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IaasApiPutModel {

    private String iamApi;
    private String networkApi;
    private String serviceApi;
    private String projectid;
    private String username;
    private String password;
    @NotBlank private String apiType;
    private String region;

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    @NotNull
    @Min(1) private Long routingDomainForIaasApi;

    public String getServiceApi() {
        return serviceApi;
    }

    public void setServiceApi(String serviceApi) {
        this.serviceApi = serviceApi;
    }

    public String getIamApi() {
        return iamApi;
    }

    public void setIamApi(String iamApi) {
        this.iamApi = iamApi;
    }

    public String getNetworkApi() {
        return networkApi;
    }

    public void setNetworkApi(String networkApi) {
        this.networkApi = networkApi;
    }

    public String getProjectid() {
        return projectid;
    }

    public void setProjectid(String projectid) {
        this.projectid = projectid;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Long getRoutingDomainForIaasApi() {
        return routingDomainForIaasApi;
    }

    public void setRoutingDomainForIaasApi(Long routingDomainForIaasApi) {
        this.routingDomainForIaasApi = routingDomainForIaasApi;
    }

    public String getApiType() {
        return apiType;
    }

    public void setApiType(String apiType) {
        this.apiType = apiType;
    }
}
