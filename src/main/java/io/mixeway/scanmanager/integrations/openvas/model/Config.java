package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.*;

@XmlRootElement(name="config")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class Config {

	private String id;
	private String name;

	@XmlElement(name="name")
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@XmlAttribute(name="id")
	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}
	public Config(String id) {
		this.setId(id);
	}
	public Config() {}
	

}
