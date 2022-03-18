package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.*;


@XmlRootElement(name="commands_response")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class CommandResponseCreateTask {
    String status;
    CreateTaskResponse createTaskResponse;

    @XmlElement(name="create_task_response")
    public CreateTaskResponse getCreateTaskResponse() {
        return createTaskResponse;
    }

    public void setCreateTaskResponse(CreateTaskResponse createTaskResponse) {
        this.createTaskResponse = createTaskResponse;
    }

    @XmlAttribute(name="status")
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
