package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="commands")
@XmlAccessorType(XmlAccessType.FIELD)
public class CommandsModifyTask {
	private Authenticate authenticate;
	@XmlElement(name="modify_task")
	private ModifyTask modifyTask;
	public Authenticate getAuthenticate() {
		return authenticate;
	}
	public void setAuthenticate(Authenticate authenticate) {
		this.authenticate = authenticate;
	}
	public ModifyTask getModifyTask() {
		return modifyTask;
	}
	public void setModifyTask(ModifyTask modifyTask) {
		this.modifyTask = modifyTask;
	}
	
	public CommandsModifyTask() {}
	public CommandsModifyTask(User user, ModifyTask modifyTask) {
		this.setAuthenticate(new Authenticate(user));
		this.setModifyTask(modifyTask);
	}

}
