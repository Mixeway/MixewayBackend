package io.mixeway.rest.project.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IaasApiPutModel {
    @NotEmpty
    private String iamApi;
    @NotBlank private String networkApi;
    @NotBlank private String serviceApi;
    @NotBlank private String projectid;
    @NotBlank private String username;
    @NotBlank private String password;
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
}
