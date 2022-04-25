package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlRootElement(name="get_scanners_response")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class GetScannersResponse {
    List<Scanner> scanner;

    @XmlElement(name="scanner")
    public List<Scanner> getScanner() {
        return scanner;
    }

    public void setScanner(List<Scanner> scanner) {
        this.scanner = scanner;
    }
}
