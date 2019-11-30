package io.mixeway.pojo;

import io.mixeway.db.entity.WebApp;

public class WebAppListDto {
	WebApp webApp;
	String description;
	int vulns;
	public WebApp getWebApp() {
		return webApp;
	}
	public void setWebApp(WebApp webApp) {
		this.webApp = webApp;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public int getVulns() {
		return vulns;
	}
	public void setVulns(int vulns) {
		this.vulns = vulns;
	}
	
	
	

}
