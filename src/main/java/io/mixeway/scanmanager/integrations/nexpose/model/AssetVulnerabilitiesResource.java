package io.mixeway.scanmanager.integrations.nexpose.model;

import java.util.Date;
import java.util.List;

public class AssetVulnerabilitiesResource {

    private String id;
    private int instances;
    private Date since;
    private String status;
    private List<Result> results;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public int getInstances() {
        return instances;
    }

    public void setInstances(int instances) {
        this.instances = instances;
    }

    public Date getSince() {
        return since;
    }

    public void setSince(Date since) {
        this.since = since;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public List<Result> getResults() {
        return results;
    }

    public void setResults(List<Result> results) {
        this.results = results;
    }
}
