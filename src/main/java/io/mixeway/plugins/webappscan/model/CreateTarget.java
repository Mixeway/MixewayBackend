package io.mixeway.plugins.webappscan.model;

import io.mixeway.db.entity.WebApp;

public class CreateTarget {
	private String address;
	private String description;
	private String type;
	private int criticality;
	
	public CreateTarget(WebApp webApp) {
		this.setAddress(webApp.getUrl().trim());
		this.setDescription("System: "+webApp.getProject().getName()+", Auto scan from mixeer");
		this.setType("default");
		this.setCriticality(30);
	}
	
	public String getAddress() {
		return address;
	}
	public void setAddress(String address) {
		this.address = address;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public int getCriticality() {
		return criticality;
	}
	public void setCriticality(int criticality) {
		this.criticality = criticality;
	}
	
	

}
