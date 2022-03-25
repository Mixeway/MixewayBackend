
package io.mixeway.scanmanager.integrations.openscap.model;

import lombok.Getter;
import lombok.Setter;
import org.simpleframework.xml.Element;
import org.simpleframework.xml.ElementList;
import org.simpleframework.xml.Root;

import java.util.List;

@Getter
@Setter
@Root(strict = false)
public class Group {
    @Element(required = false)
    String title;
    @Element(required = false)
    String description;
    @ElementList(entry = "Group",inline = true,required = false)
    List<GroupRule> groups;
    @ElementList(entry = "Rule", inline = true,required = false)
    List<Rule>rules;
}
