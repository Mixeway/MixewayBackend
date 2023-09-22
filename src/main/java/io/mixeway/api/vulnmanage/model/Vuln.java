package io.mixeway.api.vulnmanage.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.utils.VulnSource;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Getter
@Setter
@Log4j2
public class Vuln {

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
			this.setSeverity(projectVulnerability.getVulnerability().getSeverity() == null ? projectVulnerability.getSeverity() : projectVulnerability.getVulnerability().getSeverity());
			this.setDescription(Objects.toString(projectVulnerability.getDescription(), "Description missing"));
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
			this.setSeverity(projectVulnerability.getVulnerability().getSeverity() == null ? projectVulnerability.getSeverity() : projectVulnerability.getVulnerability().getSeverity());
			this.setDescription(Objects.toString(projectVulnerability.getDescription(), "")+ "\n\n " + Objects.toString(projectVulnerability.getRecommendation(), ""));
			this.setProject(cp.getName());
			if (cp.getProject().getCiid() != null)
					this.setCiid(cp.getProject().getCiid());
			this.setDateCreated(projectVulnerability.getInserted());
			this.setPacketName(projectVulnerability.getSoftwarePacket().getName());
			this.setGrade(projectVulnerability.getGrade());
		} else if ((target instanceof CodeProject) && (projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_SOURCECODE) || projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULNEARBILITY_SOURCE_IAC) || projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULNEARBILITY_SOURCE_GITLEAKS) )){
			this.setGrade(projectVulnerability.getGrade());
			this.setId(projectVulnerability.getId());
			this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
			this.setSeverity(projectVulnerability.getVulnerability().getSeverity() == null ? projectVulnerability.getSeverity() : projectVulnerability.getVulnerability().getSeverity());
			//TODO: zrobienie opisu dla fortify
			this.setDescription(projectVulnerability.getDescription());
			try {
				this.setProject(projectVulnerability.getCodeProject().getName());

			this.setCiid(projectVulnerability.getCodeProject().getProject().getCiid());
			this.setLocation(projectVulnerability.getLocation());
			this.setAnalysis(projectVulnerability.getAnalysis());
			this.setDateCreated(projectVulnerability.getInserted());
			this.setType(Constants.API_SCANNER_CODE);
			}catch (Exception e){
				e.printStackTrace();
				log.info("problem with vuln for {}", projectVulnerability.getCodeProject().getName());
			}
		} else if ((target instanceof WebApp) && projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_WEBAPP)){
			this.setGrade(projectVulnerability.getGrade());
			this.setId(projectVulnerability.getId());
			this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
			this.setSeverity(projectVulnerability.getVulnerability().getSeverity() == null ? projectVulnerability.getSeverity() : projectVulnerability.getVulnerability().getSeverity());
			//this.setDescription(projectVulnerability.getDescription()+"\n\n"+projectVulnerability.getRecommendation());
			this.setDescription(Objects.toString(projectVulnerability.getDescription(), "Description missing")+"\n\n"+Objects.toString(projectVulnerability.getRecommendation(), ""));
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
			this.setSeverity(projectVulnerability.getVulnerability().getSeverity() == null ? projectVulnerability.getSeverity() : projectVulnerability.getVulnerability().getSeverity());
			this.setDescription(Objects.toString(projectVulnerability.getDescription(), "Description missing"));
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
			this.setSeverity(projectVulnerability.getVulnerability().getSeverity() == null ? projectVulnerability.getSeverity() : projectVulnerability.getVulnerability().getSeverity());
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

}
