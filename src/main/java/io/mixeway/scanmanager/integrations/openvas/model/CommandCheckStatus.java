package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.*;


@XmlRootElement(name="commands_response")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class CommandCheckStatus {
    String status;
    GetTaskResponse getTaskResponse;

    @XmlElement(name="get_tasks_response")
    public GetTaskResponse getGetTaskResponse() {
        return getTaskResponse;
    }

    public void setGetTaskResponse(GetTaskResponse getTaskResponse) {
        this.getTaskResponse = getTaskResponse;
    }

    @XmlAttribute(name="status")
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
