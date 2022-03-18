package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="create_target_response")
public class CreateTargetResponse {
    String status;
    String id;

    @XmlAttribute(name="name")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @XmlAttribute(name="id")
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
