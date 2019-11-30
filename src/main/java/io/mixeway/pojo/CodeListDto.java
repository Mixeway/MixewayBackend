package io.mixeway.pojo;

import io.mixeway.db.entity.Project;

public class CodeListDto {
	String name;
	Project project;
	String description;
	int vulns;

	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public int getVulns() {
		return vulns;
	}
	public void setVulns(int vulns) {
		this.vulns = vulns;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public Project getProject() {
		return project;
	}
	public void setProject(Project project) {
		this.project = project;
	}

	
	
	

}
