package io.mixeway.integrations.webappscan.plugin.burpee.model;

import io.mixeway.db.entity.NessusScanTemplate;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.WebApp;
import org.codehaus.jackson.annotate.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
public class ScanRequest {
    List<String> urls;
    String name;
    @JsonProperty("scan_configurations_ids")
    List<String> scan_configurations_ids;

    ScanRequest() {}

    /**
     * Create Scan Request for BurpEE based on given WebApp and Scanner which will execute a request.
     * Name and urls are the same and value is WebApp.url
     *
     * @param webApp webapplication to be scanned
     * @param scanner scanner which will execute a scan
     */
    public ScanRequest(WebApp webApp, Scanner scanner){
        this.urls = Collections.singletonList(webApp.getUrl());
        this.name = webApp.getUrl();
        this.scan_configurations_ids = scanner
                .getNessusScanTemplates()
                .stream()
                .map(NessusScanTemplate::getUuid)
                .distinct()
                .collect(Collectors.toList());
    }

    public List<String> getUrls() {
        return urls;
    }

    public void setUrls(List<String> urls) {
        this.urls = urls;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getScan_configurations_ids() {
        return scan_configurations_ids;
    }

    public void setScan_configurations_ids(List<String> scan_configurations_ids) {
        this.scan_configurations_ids = scan_configurations_ids;
    }
}
