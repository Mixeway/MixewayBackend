package io.mixeway.integrations.infrastructurescan.plugin.nexpose.model;

import java.util.List;

public class IncludedTargets {
    private List<String> addresses;

    public List<String> getAddresses() {
        return addresses;
    }

    public void setAddresses(List<String> addresses) {
        this.addresses = addresses;
    }
}
