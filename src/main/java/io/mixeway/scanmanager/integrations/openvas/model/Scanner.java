package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.*;

@XmlRootElement(name="scanner")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class Scanner {

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
	public Scanner(String id) {
		this.setId(id);
	}
	public Scanner(){}

}
