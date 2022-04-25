package io.mixeway.scanmanager.integrations.openvas.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.InfraScan;
import org.springframework.stereotype.Service;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.UUID;

@Service
public class XmlOperationBuilder {

	public static String buildGetConfig(User user) throws JAXBException {
		CommandsGetConfig cgc = new CommandsGetConfig(user);
		JAXBContext jaxbContext = JAXBContext.newInstance(CommandsGetConfig.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(cgc, sw);
		return sw.toString();
	}
	public static String buildGetScanners(User user) throws JAXBException {
		CommandsGetScanner cgs = new CommandsGetScanner(user);
		JAXBContext jaxbContext = JAXBContext.newInstance(CommandsGetScanner.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(cgs, sw);
		return sw.toString();
	}
	public static String buildCreateTarget(User user, String target, String targetName) throws JAXBException {
		CommandsCreateTarget cct = new CommandsCreateTarget(user);
		CreateTarget ct = new CreateTarget();
		ct.setHosts(target);
		ct.setName(targetName);
		cct.setCreateTarget(ct);
		JAXBContext jaxbContext = JAXBContext.newInstance(CommandsCreateTarget.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(cct, sw);
		return sw.toString();
		
	}
	public String buildDeleteTarget(User user, HashMap<String, String> target) throws JAXBException {
		CommandsDeleteTarget cdt = new CommandsDeleteTarget(user);
		DeleteTarget dt = new DeleteTarget();
		dt.setTargetId(target.get(Constants.TARGET_ID));
		cdt.setDeleteTarget(dt);
		JAXBContext jaxbContext = JAXBContext.newInstance(CommandsDeleteTarget.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(cdt, sw);
		return sw.toString();
		
	}
	public static String buildCreateTask(User user, InfraScan infraScan) throws JAXBException {
		CommandsCreateTask cct = new CommandsCreateTask(user);
		CreateTask ct = new CreateTask();
		ct.setConfig(new Config(infraScan.getNessus().getConfigId()));
		ct.setScanner(new Scanner(infraScan.getNessus().getScannerid()));
		ct.setTarget(new Target(infraScan.getTargetId()));
		ct.setName(infraScan.getProject().getName()+(infraScan.getIsAutomatic()?"-auto-":"-manual-")+ UUID.randomUUID().toString());
		cct.setCreateTask(ct);
		JAXBContext jaxbContext = JAXBContext.newInstance(CommandsCreateTask.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(cct, sw);
		return sw.toString();
		
	}
	public String buildModifyTask(User user, HashMap<String, String> target) throws JAXBException {
		CommandsModifyTask cmt = new CommandsModifyTask(user, new ModifyTask(target.get(Constants.TASK_ID), new Target(target.get(Constants.TARGET_ID))));
		JAXBContext jaxbContext = JAXBContext.newInstance(CommandsModifyTask.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(cmt, sw);
		return sw.toString();
		
	}
	public static String buildStartTask(User user, InfraScan infraScan) throws JAXBException {
		CommandsStartTask cst = new CommandsStartTask(user, new StartTask(infraScan.getTaskId()));
		JAXBContext jaxbContext = JAXBContext.newInstance(CommandsStartTask.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(cst, sw);
		return sw.toString();
		
	}
	public static String buildGetTask(User user, InfraScan infraScan) throws JAXBException {
		CommandsGetTasks cgt = new CommandsGetTasks(user, new GetTask(infraScan.getTaskId()));
		JAXBContext jaxbContext = JAXBContext.newInstance(CommandsGetTasks.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(cgt, sw);
		return sw.toString();
		
	}
	public static String buildGetReport(User user, InfraScan infraScan) throws JAXBException {
		CommandsGetReport cgr = new CommandsGetReport(user, new Report(infraScan.getReportId()));
		JAXBContext jaxbContext = JAXBContext.newInstance(CommandsGetReport.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(cgr, sw);
		return sw.toString();
		
	}

}
