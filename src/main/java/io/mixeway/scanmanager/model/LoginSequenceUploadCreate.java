package io.mixeway.scanmanager.model;

import io.mixeway.db.entity.WebApp;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginSequenceUploadCreate {

	private String name;
	private String size;
	
	public LoginSequenceUploadCreate(WebApp webApp) {
		this.setName(webApp.getLoginSequence().getName());
		this.setSize(""+webApp.getLoginSequence().getLoginSequenceText().length());
	}
}
