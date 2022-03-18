package io.mixeway.scanmanager.integrations.openvas.model;


import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="commands")
@XmlAccessorType(XmlAccessType.FIELD)
public class CommandsDeleteTarget {
	
	
	private Authenticate authenticate;
	@XmlElement(name="delete_target")
	private DeleteTarget deleteTarget;
	public Authenticate getAuthenticate() {
		return authenticate;
	}
	public void setAuthenticate(Authenticate authenticate) {
		this.authenticate = authenticate;
	}
	public DeleteTarget getDeleteTarget() {
		return deleteTarget;
	}
	public void setDeleteTarget(DeleteTarget deleteTarget) {
		this.deleteTarget = deleteTarget;
	}
	
	public CommandsDeleteTarget() {}
	public CommandsDeleteTarget(User user) {
		this.setAuthenticate(new Authenticate(user));
	}

}
