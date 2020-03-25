package io.mixeway.integrations.codescan.plugin.fortify.model;

import java.util.ArrayList;
import java.util.List;

public class FortifyProjectAttributes {
    private String guid;
    private int attributeDefinitionId;
    private List<FortifyAttributeValue> values;

    public FortifyProjectAttributes () {}
    public FortifyProjectAttributes (String guid1, int attributeDefinitionId, String guid2) {
        List<FortifyAttributeValue> fortifyAttributeValues = new ArrayList<>();
        FortifyAttributeValue fortifyAttributeValue = new FortifyAttributeValue(guid2);
        fortifyAttributeValues.add(fortifyAttributeValue);

        this.values = fortifyAttributeValues;
        this.guid = guid1;
        this.attributeDefinitionId = attributeDefinitionId;
    }

    public String getGuid() {
        return guid;
    }

    public void setGuid(String guid) {
        this.guid = guid;
    }

    public int getAttributeDefinitionId() {
        return attributeDefinitionId;
    }

    public void setAttributeDefinitionId(int attributeDefinitionId) {
        this.attributeDefinitionId = attributeDefinitionId;
    }

    public List<FortifyAttributeValue> getValues() {
        return values;
    }

    public void setValues(List<FortifyAttributeValue> values) {
        this.values = values;
    }
}
