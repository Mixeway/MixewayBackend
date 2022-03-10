package io.mixeway.scanmanager.integrations.burpee.model;

import io.mixeway.db.entity.NessusScanTemplate;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.WebApp;
import io.mixeway.utils.VaultHelper;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * @author gsiewruk
 */

public class ScanRequest {
    List<String> urls;
    String name;
    List<ScanConfig> scan_configurations;
    List<AuthLogins> application_logins;

    ScanRequest() {}

    /**
     * Create Scan Request for BurpEE based on given WebApp and Scanner which will execute a request.
     * Name and urls are the same and value is WebApp.url
     *
     * @param webApp webapplication to be scanned
     * @param scanner scanner which will execute a scan
     */
    public ScanRequest(WebApp webApp, Scanner scanner, VaultHelper vaultHelper){
        this.urls = Collections.singletonList(webApp.getUrl());
        this.name = webApp.getUrl();
        this.scan_configurations = prepareConfigs(scanner.getNessusScanTemplates());
        if (this.isPasswordAuthSet(webApp)){
            List<AuthLogins> authLogins = new ArrayList<>();
            authLogins.add(new AuthLogins(vaultHelper.getPassword(webApp.getPassword()), webApp.getUsername()));
            this.application_logins = authLogins;
        }
    }

    private boolean isPasswordAuthSet(WebApp webApp) {
        return StringUtils.isNotBlank(webApp.getPassword()) && StringUtils.isNotBlank(webApp.getUsername());
    }

    List<ScanConfig> prepareConfigs(Set<NessusScanTemplate> nessusScanTemplateSet){
        List<ScanConfig> scanConfigs = new ArrayList<>();
        for (NessusScanTemplate nessusScanTemplate : nessusScanTemplateSet){
            scanConfigs.add(new ScanConfig(nessusScanTemplate));
        }
        return scanConfigs;
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

    public List<ScanConfig> getScan_configurations() {
        return scan_configurations;
    }

    public void setScan_configurations(List<ScanConfig> scan_configurations) {
        this.scan_configurations = scan_configurations;
    }
}
