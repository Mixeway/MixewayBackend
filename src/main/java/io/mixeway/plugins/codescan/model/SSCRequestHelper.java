package io.mixeway.plugins.codescan.model;

import org.springframework.http.HttpEntity;
import org.springframework.web.client.RestTemplate;

public class SSCRequestHelper {
    RestTemplate restTemplate;
    HttpEntity httpEntity;
    public SSCRequestHelper(RestTemplate restTemplate, HttpEntity httpEntity){
        this.httpEntity = httpEntity;
        this.restTemplate = restTemplate;
    }

    public RestTemplate getRestTemplate() {
        return restTemplate;
    }

    public void setRestTemplate(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public HttpEntity getHttpEntity() {
        return httpEntity;
    }

    public void setHttpEntity(HttpEntity httpEntity) {
        this.httpEntity = httpEntity;
    }
}
