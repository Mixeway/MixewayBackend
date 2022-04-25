package io.mixeway.scanmanager.integrations.burpee.model;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.NessusScanTemplate;

public class ScanConfig {
    String name;
    String type;

    public ScanConfig(){}
    public ScanConfig(NessusScanTemplate nessusScanTemplate){
        this.name = nessusScanTemplate.getName();
        this.type = Constants.BURP_NAMED_CONFIGURATION;
    }
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
