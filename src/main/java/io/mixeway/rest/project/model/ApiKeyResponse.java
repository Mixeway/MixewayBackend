package io.mixeway.rest.project.model;

public class ApiKeyResponse {
    String apiKey;

    public ApiKeyResponse(String apikey){
        this.apiKey = apikey;
    }
    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }
}
