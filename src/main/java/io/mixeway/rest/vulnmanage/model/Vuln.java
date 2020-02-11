package io.mixeway.rest.vulnmanage.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mixeway.db.entity.RoutingDomain;

public class Vuln {
	private String vulnerabilityName;
	private String type;
	private String severity;
	private String description;
	private String ipAddress;
	private String port;
	private String ipProtocol;
	private String baseURL;
	private String location;
	private String project;
	private String analysis;
	private String hostname;
	private String hostType;
	private String requirementCode;
	private String requirement;
	private String packetName;
	private String dateCreated;
	private String ciid;
	@JsonInclude(JsonInclude.Include.NON_DEFAULT)
	private String routingDomainName;

	public String getRoutingDomainName() {
		return routingDomainName;
	}

	public void setRoutingDomainName(String routingDomainName) {
		this.routingDomainName = routingDomainName;
	}

	public String getCiid() {
		return ciid;
	}
	public void setCiid(String ciid) {
		this.ciid = ciid;
	}
	public String getDateCreated() {
		return dateCreated;
	}
	public void setDateCreated(String dateCreated) {
		this.dateCreated = dateCreated;
	}
	public String getVulnerabilityName() {
		return vulnerabilityName;
	}
	public void setVulnerabilityName(String vulnerabilityName) {
		this.vulnerabilityName = vulnerabilityName;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getSeverity() {
		return severity;
	}
	public void setSeverity(String severity) {
		this.severity = severity;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public String getIpAddress() {
		return ipAddress;
	}
	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}
	public String getPort() {
		return port;
	}
	public void setPort(String port) {
		this.port = port;
	}
	public String getIpProtocol() {
		return ipProtocol;
	}
	public void setIpProtocol(String ipProtocol) {
		this.ipProtocol = ipProtocol;
	}
	public String getBaseURL() {
		return baseURL;
	}
	public void setBaseURL(String baseURL) {
		this.baseURL = baseURL;
	}
	public String getLocation() {
		return location;
	}
	public void setLocation(String location) {
		this.location = location;
	}
	public String getProject() {
		return project;
	}
	public void setProject(String project) {
		this.project = project;
	}
	public String getAnalysis() {
		return analysis;
	}
	public void setAnalysis(String analysis) {
		this.analysis = analysis;
	}
	public String getHostname() {
		return hostname;
	}
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}
	public String getHostType() {
		return hostType;
	}
	public void setHostType(String hostType) {
		this.hostType = hostType;
	}
	public String getRequirementCode() {
		return requirementCode;
	}
	public void setRequirementCode(String requirementCode) {
		this.requirementCode = requirementCode;
	}
	public String getRequirement() {
		return requirement;
	}
	public void setRequirement(String requirement) {
		this.requirement = requirement;
	}
	public String getPacketName() {
		return packetName;
	}
	public void setPacketName(String packetName) {
		this.packetName = packetName;
	}
	
	
	

}
