package io.mixeway.plugins.webappscan.model;

import io.mixeway.db.entity.WebApp;

public class LoginSequenceUploadCreate {

	private String name;
	private String size;
	
	public LoginSequenceUploadCreate(WebApp webApp) {
		this.setName(webApp.getLoginSequence().getName());
		this.setSize(""+webApp.getLoginSequence().getLoginSequenceText().length());
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getSize() {
		return size;
	}
	public void setSize(String size) {
		this.size = size;
	}
	
}
