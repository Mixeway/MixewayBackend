package io.mixeway.scanmanager.integrations.fortify.model;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
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
}
