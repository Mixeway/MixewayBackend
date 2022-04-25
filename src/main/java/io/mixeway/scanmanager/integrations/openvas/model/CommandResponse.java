package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAttribute;

public interface CommandResponse {
    @XmlAttribute
    String getStatus();
    void setStatus(String status);
}
