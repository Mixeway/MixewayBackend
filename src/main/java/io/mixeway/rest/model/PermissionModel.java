package io.mixeway.rest.model;

import java.util.Map;

public class PermissionModel {
    Map.Entry<String, String> apiType;
    boolean status;

    public Map.Entry<String, String> getApiType() {
        return apiType;
    }

    public void setApiType(Map.Entry<String, String> apiType) {
        this.apiType = apiType;
    }

    public boolean isStatus() {
        return status;
    }

    public void setStatus(boolean status) {
        this.status = status;
    }
}
