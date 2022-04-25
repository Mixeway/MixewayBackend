package io.mixeway.api.project.model;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

@Getter
@Setter
public class WebAppPutModel {
    private String webAppUrl;
    private String webAppHeaders;
    private boolean scanPublic;
    private String webAppUsername;
    private String webAppPassword;
    private String appClient;
    @NotNull
    @Min(1)
    private Long routingDomainForAsset;

    public boolean isPasswordAuthSet(){
        return StringUtils.isNotBlank(webAppPassword) && StringUtils.isNotBlank(webAppUsername);
    }



}
