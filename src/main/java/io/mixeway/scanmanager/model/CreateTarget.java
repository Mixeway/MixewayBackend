package io.mixeway.scanmanager.model;

import io.mixeway.db.entity.WebApp;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class CreateTarget {
	private String address;
	private String description;
	private String type;
	private int criticality;
	
	public CreateTarget(WebApp webApp) {
		this.setAddress(webApp.getUrl().trim());
		this.setDescription("System: "+webApp.getProject().getName()+", Auto scan from mixeer");
		this.setType("default");
		this.setCriticality(30);
	}
}
