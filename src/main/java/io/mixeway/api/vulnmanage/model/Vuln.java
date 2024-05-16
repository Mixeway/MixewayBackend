package io.mixeway.api.vulnmanage.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.utils.VulnSource;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Objects;

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

	public <S extends VulnSource> Vuln(ProjectVulnerability projectVulnerability, String hostname, String ipAddress, S target, String type) throws UnknownHostException, URISyntaxException {
		this.setId(projectVulnerability.getId());
		this.setSeverity(projectVulnerability.getVulnerability().getSeverity() == null ? projectVulnerability.getSeverity() : projectVulnerability.getVulnerability().getSeverity());
		this.setDescription(Objects.toString(projectVulnerability.getDescription(), "Description missing"));
		this.setDateCreated(projectVulnerability.getInserted().toString());

		switch (type) {
			case Constants.API_SCANNER_PACKAGE:
				if (target instanceof Asset) {
					this.setType(Constants.API_SCANNER_PACKAGE);
					this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
					this.setHostname(hostname);
					this.setLocation(((Asset) target).getName());
					this.setProject(projectVulnerability.getProject().getName());
					this.setCiid(projectVulnerability.getProject().getCiid());
					this.setPacketName(projectVulnerability.getSoftwarePacket().getName());
				} else if (target instanceof CodeProject && projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_OPENSOURCE)) {
					CodeProject cp = (CodeProject) target;
					this.setLocation(cp.getName());
					this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
					this.setDescription(Objects.toString(projectVulnerability.getDescription(), "") + "\n\n " + Objects.toString(projectVulnerability.getRecommendation(), ""));
					this.setProject(cp.getName());
					this.setCiid(cp.getProject().getCiid());
					this.setPacketName(projectVulnerability.getSoftwarePacket().getName());
					this.setGrade(projectVulnerability.getGrade());
				}
				break;
			case Constants.API_SCANNER_CODE:
				if (target instanceof CodeProject && (projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_SOURCECODE)
						|| projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULNEARBILITY_SOURCE_IAC)
						|| projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULNEARBILITY_SOURCE_GITLEAKS))) {
					this.setGrade(projectVulnerability.getGrade());
					this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
					try {
						this.setProject(projectVulnerability.getCodeProject().getName());
						this.setCiid(projectVulnerability.getCodeProject().getProject().getCiid());
						this.setLocation(projectVulnerability.getLocation());
						this.setAnalysis(projectVulnerability.getAnalysis());
					} catch (Exception e) {
						log.info("problem with vuln for {}", projectVulnerability.getCodeProject().getName());
					}
				}
				break;
			case Constants.API_SCANNER_WEBAPP:
				if (target instanceof WebApp && projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_WEBAPP)) {
					this.setGrade(projectVulnerability.getGrade());
					this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
					this.setDescription(Objects.toString(projectVulnerability.getDescription(), "Description missing") + "\n\n" + Objects.toString(projectVulnerability.getRecommendation(), ""));
					this.setBaseURL(projectVulnerability.getWebApp().getUrl());
					this.setLocation(projectVulnerability.getLocation());
					this.setRoutingDomainName(projectVulnerability.getWebApp().getRoutingDomain() != null ?
							projectVulnerability.getWebApp().getRoutingDomain().getName().equals("Internet") ?
									projectVulnerability.getWebApp().getRoutingDomain().getName() : "Intranet" :
							projectVulnerability.getWebApp().getPublicscan() ? "Internet" : "Intranet");
					URI uri = new URI(projectVulnerability.getWebApp().getUrl());
					this.setIpAddress(uri.getHost());
					this.setPort(String.valueOf(uri.getPort()));
					this.setCiid(projectVulnerability.getWebApp().getProject().getCiid());
				}
				break;
			case Constants.API_SCANNER_OPENVAS:
				if (target instanceof Interface && projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULN_TYPE_NETWORK)) {
					this.setGrade(projectVulnerability.getGrade());
					this.setVulnerabilityName(projectVulnerability.getVulnerability().getName());
					this.setIpAddress(projectVulnerability.getAnInterface().getPrivateip() != null && !projectVulnerability.getAnInterface().getPrivateip().equals("") ?
							projectVulnerability.getAnInterface().getPrivateip() :
							projectVulnerability.getAnInterface().getFloatingip());
					this.setCiid(projectVulnerability.getAnInterface().getAsset().getProject().getCiid());
					this.setRoutingDomainName(projectVulnerability.getAnInterface().getRoutingDomain() != null ? projectVulnerability.getAnInterface().getRoutingDomain().getName() : "");
					if (projectVulnerability.getPort() != null) {
						String[] parts = projectVulnerability.getPort().split("/");
						if (parts.length == 2) {
							this.setPort(parts[0].trim().replace(" ", ""));
							this.setIpProtocol(parts[1].trim().replace(" ", ""));
						}
					}
				} else if (target instanceof Interface && projectVulnerability.getVulnerabilitySource().getName().equals(Constants.VULNEARBILITY_SOURCE_CISBENCHMARK)) {
					this.setGrade(projectVulnerability.getGrade());
					this.setVulnerabilityName(projectVulnerability.getCisRequirement().getName());
					this.setIpAddress(projectVulnerability.getAnInterface().getPrivateip() != null && !projectVulnerability.getAnInterface().getPrivateip().equals("") ?
							projectVulnerability.getAnInterface().getPrivateip() :
							projectVulnerability.getAnInterface().getFloatingip());
					this.setCiid(projectVulnerability.getAnInterface().getAsset().getProject().getCiid());
					this.setRoutingDomainName(projectVulnerability.getAnInterface().getRoutingDomain() != null ? projectVulnerability.getAnInterface().getRoutingDomain().getName() : "");
					this.setType(Constants.VULNEARBILITY_SOURCE_CISBENCHMARK);
				}
				break;
		}
	}

	public Vuln() {
	}
}
