
package io.mixeway.scanmanager.integrations.openscap.model;

import lombok.Getter;
import lombok.Setter;
import org.simpleframework.xml.Element;
import org.simpleframework.xml.ElementList;
import org.simpleframework.xml.Root;

import java.util.List;

@Getter
@Setter
@Root(strict = false,name = "Group")
public class GroupRule {
    @Element
    String title;
    @Element(required = false)
    String description;
    @ElementList(entry = "Rule", inline = true)
    List<Rule>rules;
}
