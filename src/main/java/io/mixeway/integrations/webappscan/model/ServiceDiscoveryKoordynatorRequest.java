package io.mixeway.integrations.webappscan.model;

import java.util.List;

public class ServiceDiscoveryKoordynatorRequest {
	
	List<WebAppScanModel> webApp;

	String ciid;

	public String getCiid() {
		return ciid;
	}

	public void setCiid(String ciid) {
		this.ciid = ciid;
	}

	public List<WebAppScanModel> getWebApp() {
		return webApp;
	}

	public void setWebApp(List<WebAppScanModel> webApp) {
		this.webApp = webApp;
	}
	
	

}
