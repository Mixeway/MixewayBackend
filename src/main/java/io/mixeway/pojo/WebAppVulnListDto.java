package io.mixeway.pojo;

public class WebAppVulnListDto {
	String name;
	Long occurance;
	String description;
	String severity;
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public Long getOccurance() {
		return occurance;
	}
	public void setOccurance(Long occurance) {
		this.occurance = occurance;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public String getSeverity() {
		return severity;
	}
	public void setSeverity(String severity) {
		this.severity = severity;
	}

}
