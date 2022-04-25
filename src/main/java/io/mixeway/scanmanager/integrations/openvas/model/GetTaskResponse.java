package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="get_tasks_response")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class GetTaskResponse {
    Task task;

    @XmlElement(name="task")
    public Task getTask() {
        return task;
    }

    public void setTask(Task task) {
        this.task = task;
    }
    public GetTaskResponse(){}

}
