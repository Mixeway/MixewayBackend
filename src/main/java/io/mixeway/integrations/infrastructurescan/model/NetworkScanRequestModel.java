package io.mixeway.integrations.infrastructurescan.model;

import io.mixeway.pojo.AssetToCreate;

import java.util.List;
import java.util.Optional;

public class NetworkScanRequestModel {

	private List<AssetToCreate> ipAddresses;
	public List<AssetToCreate> getIpAddresses() {
		return ipAddresses;
	}
	public void setIpAddresses(List<AssetToCreate> ipAddresses) {
		this.ipAddresses = ipAddresses;
	}
	private String projectName;
	private String ciid;
	Optional<Boolean> enableVulnManage;

	public Optional<Boolean> getEnableVulnManage() {
		return enableVulnManage;
	}

	public void setEnableVulnManage(Optional<Boolean> enableVulnManage) {
		this.enableVulnManage = enableVulnManage;
	}
	
	public String getProjectName() {
		return projectName;
	}
	public void setProjectName(String projectName) {
		this.projectName = projectName;
	}
	public String getCiid() {
		return ciid;
	}
	public void setCiid(String ciid) {
		this.ciid = ciid;
	}
	
	
	
}
