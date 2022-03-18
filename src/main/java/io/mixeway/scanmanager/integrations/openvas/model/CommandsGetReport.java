package io.mixeway.scanmanager.integrations.openvas.model;


import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="commands")
@XmlAccessorType(XmlAccessType.FIELD)
public class CommandsGetReport {
	
	private Authenticate authenticate;
	@XmlElement(name="get_reports")
	private Report report;
	public Authenticate getAuthenticate() {
		return authenticate;
	}
	public void setAuthenticate(Authenticate authenticate) {
		this.authenticate = authenticate;
	}
	public Report getReport() {
		return report;
	}
	public void setReport(Report report) {
		this.report = report;
	}
	
	public CommandsGetReport() {}
	public CommandsGetReport(User user, Report report) {
		this.setAuthenticate(new Authenticate(user));
		this.setReport(report);
	}

}
