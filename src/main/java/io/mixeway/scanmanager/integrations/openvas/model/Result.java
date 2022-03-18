package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
@XmlRootElement(name="result")
public class Result {
    String name;
    String port;
    String threat;
    String description;
    Host host;

    @XmlElement(name="host")
    public Host getHost() {
        return host;
    }

    public void setHost(Host host) {
        this.host = host;
    }

    @XmlElement(name="name")
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
    @XmlElement(name="port")
    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }

    @XmlElement(name="threat")
    public String getThreat() {
        return threat;
    }

    public void setThreat(String threat) {
        this.threat = threat;
    }

    @XmlElement(name="description")
    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
