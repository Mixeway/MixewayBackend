package io.mixeway.plugins.webappscan.model;

public class Schedule {
	private Boolean disable;
	private Boolean time_sensitive;
	private String start_date;
	public Boolean getDisable() {
		return disable;
	}
	public void setDisable(Boolean disable) {
		this.disable = disable;
	}
	public Boolean getTime_sensitive() {
		return time_sensitive;
	}
	public void setTime_sensitive(Boolean time_sensitive) {
		this.time_sensitive = time_sensitive;
	}
	public String getStart_date() {
		return start_date;
	}
	public void setStart_date(String start_date) {
		this.start_date = start_date;
	}
	
	

}
