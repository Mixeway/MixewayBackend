package io.mixeway.plugins.infrastructurescan.openvas.model;

import javax.xml.bind.annotation.XmlAttribute;

public interface CommandResponse {
    @XmlAttribute
    String getStatus();
    void setStatus(String status);
}
