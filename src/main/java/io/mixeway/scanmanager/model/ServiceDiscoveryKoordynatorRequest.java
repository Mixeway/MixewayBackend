package io.mixeway.scanmanager.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class ServiceDiscoveryKoordynatorRequest {
	
	List<WebAppScanModel> webApp;

	String ciid;

}
