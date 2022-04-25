package io.mixeway.scanmanager.integrations.openvas.model;

import java.util.List;

public class ReportXml {
	private List<Vuln> vulns;
	public List<Vuln> getVulns() {
		return vulns;
	}
	public void setVulns(List<Vuln> vulns) {
		this.vulns = vulns;
	}

	public ReportXml(List<Vuln> v) {
		this.setVulns(v);
	}
	

}
