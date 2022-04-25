package io.mixeway.api.vulnmanage.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class ScannedAddress {
    private String ip;
    private  String os;
    private List<NetworkService> networkServices;

}
