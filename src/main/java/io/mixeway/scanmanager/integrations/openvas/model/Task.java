package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.*;

@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
@XmlRootElement(name="task")
public class Task {
	private String id;
	private String status;

	@XmlElement(name="status")
	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	@XmlAttribute(name="id")
	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}
	public Task(String id) {
		this.setId(id);
	}
	public Task(){}

}
