package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.*;


@XmlRootElement(name="commands_response")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class CommandResponseCreateTarget {
    String status;
    CreateTargetResponse createTargetResponse;

    @XmlElement(name="create_target_response")
    public CreateTargetResponse getCreateTargetResponse() {
        return createTargetResponse;
    }

    public void setCreateTargetResponse(CreateTargetResponse createTargetResponse) {
        this.createTargetResponse = createTargetResponse;
    }

    @XmlAttribute(name="status")
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
