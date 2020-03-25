package io.mixeway.integrations.infrastructurescan.model;

import io.mixeway.pojo.AssetToCreate;

import java.util.List;

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
