package io.mixeway.scanmanager.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Optional;

@Getter
@Setter
public class NetworkScanRequestModel {

	private List<AssetToCreate> ipAddresses;
	private String projectName;
	private String ciid;
	Optional<Boolean> enableVulnManage;

	
	
}
