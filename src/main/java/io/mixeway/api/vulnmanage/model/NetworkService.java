package io.mixeway.api.vulnmanage.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class NetworkService {
    private String netProto;
    private String appProto;
    private int port;
    private String status;
    private String name;
}
