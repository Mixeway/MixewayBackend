package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.*;


@XmlRootElement(name="commands_response")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class CommandResponseStartTask {
    String status;
    StartTaskResponse startTaskResponse;

    @XmlElement(name="start_task_response")
    public StartTaskResponse getStartTaskResponse() {
        return startTaskResponse;
    }

    public void setStartTaskResponse(StartTaskResponse startTaskResponse) {
        this.startTaskResponse = startTaskResponse;
    }


    @XmlAttribute(name="status")
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
