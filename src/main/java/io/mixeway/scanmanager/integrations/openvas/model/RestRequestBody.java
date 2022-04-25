package io.mixeway.scanmanager.integrations.openvas.model;

import java.util.HashMap;

public class RestRequestBody {
	private User user;
	private HashMap<String, String> params;
	public User getUser() {
		return user;
	}
	public void setUser(User user) {
		this.user = user;
	}
	public HashMap<String, String> getParams() {
		return params;
	}
	public void setParams(HashMap<String, String> params) {
		this.params = params;
	}
	
	

}
