package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
@XmlRootElement(name="report")
public class ReportSecondLvl {
    Results results;
    Host host;

    @XmlElement(name="host")
    public Host getHost() {
        return host;
    }

    public void setHost(Host host) {
        this.host = host;
    }

    @XmlElement(name="results")
    public Results getResults() {
        return results;
    }

    public void setResults(Results results) {
        this.results = results;
    }
}
