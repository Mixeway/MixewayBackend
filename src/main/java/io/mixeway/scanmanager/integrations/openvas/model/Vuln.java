package io.mixeway.scanmanager.integrations.openvas.model;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Vuln {
	
	private String name;
	private String threat;
	private String port;
	private String host;
	private String desc;
	
	
}
