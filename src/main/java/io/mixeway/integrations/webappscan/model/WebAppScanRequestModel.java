package io.mixeway.integrations.webappscan.model;

import java.util.List;
import java.util.Optional;

public class WebAppScanRequestModel {
	
	List<WebAppScanModel> webApp;
	Optional<String> ciid;
	Optional<String> projectName;
	Optional<Boolean> enableVulnManage;

	public Optional<Boolean> getEnableVulnManage() {
		return enableVulnManage;
	}

	public void setEnableVulnManage(Optional<Boolean> enableVulnManage) {
		this.enableVulnManage = enableVulnManage;
	}

	public Optional<String> getProjectName() {
		return projectName;
	}

	public void setProjectName(Optional<String> projectName) {
		this.projectName = projectName;
	}

	public Optional<String> getCiid() {
		return ciid;
	}

	public void setCiid(Optional<String> ciid) {
		this.ciid = ciid;
	}


	public List<WebAppScanModel> getWebApp() {
		return webApp;
	}

	public void setWebApp(List<WebAppScanModel> webApp) {
		this.webApp = webApp;
	}
	
	

}
