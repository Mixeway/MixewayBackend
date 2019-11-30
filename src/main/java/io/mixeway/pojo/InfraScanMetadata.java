package io.mixeway.pojo;

import java.util.List;

public class InfraScanMetadata {
    List<ScannedAddress> scannedAddresses;

    public List<ScannedAddress> getScannedAddresses() {
        return scannedAddresses;
    }

    public void setScannedAddresses(List<ScannedAddress> scannedAddresses) {
        this.scannedAddresses = scannedAddresses;
    }
}
