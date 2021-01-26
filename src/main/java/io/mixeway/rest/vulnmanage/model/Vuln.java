package io.mixeway.rest.vulnmanage.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.pojo.VulnSource;
import io.mixeway.rest.vulnmanage.service.GetVulnerabilitiesService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Vuln {
	private static final Logger log = LoggerFactory.getLogger(Vuln.class);

	private Long id;
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
	private int grade;
	@JsonInclude(JsonInclude.Include.NON_DEFAULT)
	private String routingDomainName;

    public <S extends VulnSource> Vuln(ProjectVulnerability projectVulnerability, String hostname, String ipAddress, S target, String type) throws UnknownHostException {
		if ((target instanceof Asset) && type.equals(Constants.API_SCANNER_PACKAGE)) {
			this.setId(projectVulnerability.getId());
			this.setType(Constants.API_SCANNER_PACKAGE);
			this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
			this.setSeverity(projectVulnerability.getSeverity());
			this.setDescription(projectVulnerability.getDescription());
			this.setHostname(hostname);
			this.setLocation(((Asset) target).getName());
			this.setProject(projectVulnerability.getProject().getName());
			this.setCiid(projectVulnerability.getProject().getCiid());
			this.setDateCreated(projectVulnerability.getInserted());
			this.setPacketName(projectVulnerability.getSoftwarePacket().getName());
		} else if ((target instanceof CodeProject) && projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_OPENSOURCE)){
			CodeProject cp = (CodeProject)target;
			this.setId(projectVulnerability.getId());
			this.setLocation(cp.getName());
			this.setType(Constants.API_SCANNER_PACKAGE);
			this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
			this.setSeverity(projectVulnerability.getSeverity());
			this.setDescription(projectVulnerability.getRecommendation()+ " " + projectVulnerability.getDescription());
			this.setProject(cp.getName());
			if (cp.getCodeGroup().getProject().getCiid() != null)
					this.setCiid(cp.getCodeGroup().getProject().getCiid());
			this.setDateCreated(projectVulnerability.getInserted());
			this.setPacketName(projectVulnerability.getSoftwarePacket().getName());
			this.setGrade(projectVulnerability.getGrade());
		} else if ((target instanceof CodeProject) && projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_SOURCECODE)){
			this.setGrade(projectVulnerability.getGrade());
			this.setId(projectVulnerability.getId());
			this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
			this.setSeverity(projectVulnerability.getSeverity());
			//TODO: zrobienie opisu dla fortify
			this.setDescription(projectVulnerability.getDescription());
			try {
				this.setProject(projectVulnerability.getCodeProject().getCodeGroup().getName());

			this.setCiid(projectVulnerability.getCodeProject().getCodeGroup().getProject().getCiid());
			this.setLocation(projectVulnerability.getLocation());
			this.setAnalysis(projectVulnerability.getAnalysis());
			this.setDateCreated(projectVulnerability.getInserted());
			this.setType(Constants.API_SCANNER_CODE);
			}catch (Exception e){
				log.info("asd");
			}
		} else if ((target instanceof WebApp) && projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_WEBAPP)){
			this.setGrade(projectVulnerability.getGrade());
			this.setId(projectVulnerability.getId());
			this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
			this.setSeverity(projectVulnerability.getSeverity());
			this.setDescription(projectVulnerability.getDescription()+"\n\n"+projectVulnerability.getRecommendation());
			this.setBaseURL(projectVulnerability.getWebApp().getUrl());
			this.setLocation(projectVulnerability.getLocation());
			if (projectVulnerability.getWebApp().getRoutingDomain() != null) {
				this.setRoutingDomainName(projectVulnerability.getWebApp().getRoutingDomain().getName().equals("Internet") ? projectVulnerability.getWebApp().getRoutingDomain().getName() : "Intranet");
			} else {
				this.setRoutingDomainName(projectVulnerability.getWebApp().getPublicscan() ? "Internet" : "Intranet");
			}

			String ipA = getIpAddressFromUrl(projectVulnerability.getWebApp().getUrl());
			String ipP = getPortFromUrl(projectVulnerability.getWebApp().getUrl());
			this.setIpAddress(ipA);
			if (projectVulnerability.getWebApp().getProject().getCiid() != null && !projectVulnerability.getWebApp().getProject().getCiid().isEmpty())
				this.setCiid(projectVulnerability.getWebApp().getProject().getCiid());
			//TODO
			this.setDateCreated(projectVulnerability.getWebApp().getLastExecuted());
			this.setPort(ipP);
			this.setType(Constants.API_SCANNER_WEBAPP);
		} else if ((target instanceof Interface) && projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_NETWORK)){
			this.setId(projectVulnerability.getId());
			this.setGrade(projectVulnerability.getGrade());
			this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
			this.setSeverity(projectVulnerability.getSeverity());
			this.setDescription(projectVulnerability.getDescription());
			try {
				if ( projectVulnerability.getAnInterface().getPrivateip() == null && projectVulnerability.getAnInterface().getPrivateip().equals("") )
					this.setIpAddress(projectVulnerability.getAnInterface().getFloatingip());
				else
					this.setIpAddress(projectVulnerability.getAnInterface().getPrivateip());
			} catch (NullPointerException e) {
				this.setIpAddress("null ");
			}
			this.setDateCreated(projectVulnerability.getInserted());
			if (projectVulnerability.getAnInterface().getAsset().getProject().getCiid() != null && !projectVulnerability.getAnInterface().getAsset().getProject().getCiid().isEmpty())
				this.setCiid(projectVulnerability.getAnInterface().getAsset().getProject().getCiid());
			this.setRoutingDomainName(projectVulnerability.getAnInterface().getRoutingDomain() != null ? projectVulnerability.getAnInterface().getRoutingDomain().getName() : "");
			try {
				this.setPort(projectVulnerability.getPort().split("/")[0].trim().replace(" ",""));
				this.setIpProtocol(projectVulnerability.getPort().split("/")[1].trim().replace(" ", ""));
			} catch (ArrayIndexOutOfBoundsException | NullPointerException ignored){ }
			this.setType(Constants.API_SCANNER_OPENVAS);
		} else if ((target instanceof Interface) && projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULNEARBILITY_SOURCE_CISBENCHMARK)) {
			this.setId(projectVulnerability.getId());
			this.setGrade(projectVulnerability.getGrade());
			this.setVulnerabilityName(projectVulnerability.getCisRequirement().getName());
			this.setSeverity(projectVulnerability.getSeverity());
			this.setDescription(projectVulnerability.getDescription());
			try {
				if ( projectVulnerability.getAnInterface().getPrivateip() == null && projectVulnerability.getAnInterface().getPrivateip().equals("") )
					this.setIpAddress(projectVulnerability.getAnInterface().getFloatingip());
				else
					this.setIpAddress(projectVulnerability.getAnInterface().getPrivateip());
			} catch (NullPointerException e) {
				this.setIpAddress("null");
			}
			this.setDateCreated(projectVulnerability.getInserted());
			if (projectVulnerability.getAnInterface().getAsset().getProject().getCiid() != null && !projectVulnerability.getAnInterface().getAsset().getProject().getCiid().isEmpty())
				this.setCiid(projectVulnerability.getAnInterface().getAsset().getProject().getCiid());
			this.setRoutingDomainName(projectVulnerability.getAnInterface().getRoutingDomain() != null ? projectVulnerability.getAnInterface().getRoutingDomain().getName() : "");
			this.setType(Constants.VULNEARBILITY_SOURCE_CISBENCHMARK);
		}

    }
    public Vuln(){}

	public String getPortFromUrl(String url){
		String port = null;
		try {
			port = url.split(":")[2].split("/")[0];
		} catch(Exception e){
			log.debug("Port is not visible on {}", url);
		}
		if (port==null){
			if (url.split(":")[0].equals("http")){
				port="80";
			} else{
				port = "443";
			}
		}

		return port;
	}
	public String getIpAddressFromUrl(String url) throws UnknownHostException {
		String ipA = null;
		Pattern p = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(?:\\/\\d{2})?");
		Matcher m = p.matcher(url);
		try {
			if (m.find())
				ipA = m.group(0);
			else {
				String tmp;
				if (url.split("://")[1].contains(":")) {
					tmp = url.split("://")[1].split(":")[0];
				} else if (url.split("://")[1].contains("/")) {
					tmp = url.split("://")[1].split("/")[0];
				} else
					tmp = url.split("://")[1];
				InetAddress address = InetAddress.getByName(tmp);
				ipA = address.getHostAddress();
			}
		}catch (Exception e){
			log.debug("Exception during hostname resolution for {}",url);
		}

		return ipA;
	}


	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public int getGrade() {
		return grade;
	}

	public void setGrade(int grade) {
		this.grade = grade;
	}

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
