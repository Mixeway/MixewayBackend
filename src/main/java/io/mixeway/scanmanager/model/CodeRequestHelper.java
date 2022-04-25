package io.mixeway.scanmanager.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpEntity;
import org.springframework.web.client.RestTemplate;

@Getter
@Setter
@AllArgsConstructor
public class CodeRequestHelper {
    RestTemplate restTemplate;
    HttpEntity httpEntity;


}
