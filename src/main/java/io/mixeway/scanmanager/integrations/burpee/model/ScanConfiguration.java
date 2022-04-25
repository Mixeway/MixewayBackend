package io.mixeway.scanmanager.integrations.burpee.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;
import java.util.List;

/**
 * @author gsiewruk
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScanConfiguration implements Serializable {
    List<Configuration> scan_configurations;

    public List<Configuration> getScan_configurations() {
        return scan_configurations;
    }

    public void setScan_configurations(List<Configuration> scan_configurations) {
        this.scan_configurations = scan_configurations;
    }
}
