package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
@XmlRootElement(name="results")
public class Results {
    List<Result> results;

    @XmlElement(name="result")
    public List<Result> getResults() {
        return results;
    }

    public void setResults(List<Result> results) {
        this.results = results;
    }
}
