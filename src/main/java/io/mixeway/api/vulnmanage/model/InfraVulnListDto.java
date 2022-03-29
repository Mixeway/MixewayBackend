package io.mixeway.api.vulnmanage.model;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InfraVulnListDto {

	private String infraVuln;
	private Long occurance;
	private String description;
	private String severity;

}
