package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="commands")
@XmlAccessorType(XmlAccessType.FIELD)
public class CommandsCreateTarget {
	private Authenticate authenticate;
	@XmlElement(name="create_target")
	private CreateTarget createTarget;
	public Authenticate getAuthenticate() {
		return authenticate;
	}
	public void setAuthenticate(Authenticate authenticate) {
		this.authenticate = authenticate;
	}
	public CreateTarget getCreateTarget() {
		return createTarget;
	}
	public void setCreateTarget(CreateTarget createTarget) {
		this.createTarget = createTarget;
	}
	
	public CommandsCreateTarget() {}
	public CommandsCreateTarget(User user) {
		this.setAuthenticate(new Authenticate(user));
	}

}
