package io.mixeway.scanmanager.integrations.nessus.model;

import io.mixeway.config.Constants;

public class CreateFolderRequest {

	private String name;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
	public CreateFolderRequest() {
		this.setName(Constants.NESSUS_FOLDER);
	}
}
