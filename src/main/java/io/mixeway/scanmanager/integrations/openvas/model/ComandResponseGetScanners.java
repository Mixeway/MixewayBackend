package io.mixeway.scanmanager.integrations.openvas.model;

import javax.xml.bind.annotation.*;


@XmlRootElement(name="commands_response")
@XmlAccessorType(XmlAccessType.PUBLIC_MEMBER)
public class ComandResponseGetScanners {
    String status;
    GetScannersResponse getScannersResponse;

    @XmlElement(name="get_scanners_response")
    public GetScannersResponse getGetScannersResponse() {
        return getScannersResponse;
    }

    public void setGetScannersResponse(GetScannersResponse getScannersResponse) {
        this.getScannersResponse = getScannersResponse;
    }

    @XmlAttribute(name="status")
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
