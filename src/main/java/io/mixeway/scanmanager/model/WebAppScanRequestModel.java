package io.mixeway.scanmanager.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Optional;

@Getter
@Setter
public class WebAppScanRequestModel {
	
	List<WebAppScanModel> webApp;
	Optional<String> ciid;
	Optional<String> projectName;
	Optional<Boolean> enableVulnManage;

}
