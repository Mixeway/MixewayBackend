package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.*;


@XmlRootElement(name="commands_response")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class ComandResponseGetConfig {
    String status;
    GetConfigResponse getConfigResponse;

    @XmlElement(name="get_configs_response")
    public GetConfigResponse getGetConfigResponse() {
        return getConfigResponse;
    }

    public void setGetConfigResponse(GetConfigResponse getConfigResponse) {
        this.getConfigResponse = getConfigResponse;
    }

    @XmlAttribute(name="status")
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
