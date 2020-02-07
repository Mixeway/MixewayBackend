package io.mixeway.plugins.codescan.fortify.model;

public class FortifyAttributeValue {
    private String guid;

    public FortifyAttributeValue() {}
    public FortifyAttributeValue(String guid) {
        this.guid = guid;
    }

    public String getGuid() {
        return guid;
    }

    public void setGuid(String guid) {
        this.guid = guid;
    }
}
