package io.mixeway.scanmanager.integrations.nessus.model;

public class Settings {
	private String name;
	private String description;
	private String enabled;
	private int folder_id;
	private String text_targets;
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public String getEnabled() {
		return enabled;
	}
	public void setEnabled(String enabled) {
		this.enabled = enabled;
	}
	public int getFolder_id() {
		return folder_id;
	}
	public void setFolder_id(int folder_id) {
		this.folder_id = folder_id;
	}
	public String getText_targets() {
		return text_targets;
	}
	public void setText_targets(String text_targets) {
		this.text_targets = text_targets;
	}
	
	

}
