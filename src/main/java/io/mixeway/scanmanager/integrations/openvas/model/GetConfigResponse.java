package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
@XmlRootElement(name="get_configs_response")
public class GetConfigResponse {
    List<Config> config;

    @XmlElement(name="config")
    public List<Config> getConfig() {
        return config;
    }

    public void setConfig(List<Config> config) {
        this.config = config;
    }
}
