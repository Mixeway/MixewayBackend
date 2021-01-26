/*
 * @created  2021-01-21 : 21:06
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.integrations.audit.plugins.openscap.model;

import org.simpleframework.xml.Element;
import org.simpleframework.xml.ElementList;
import org.simpleframework.xml.Root;

import java.util.List;

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

    public void setGroups(List<GroupRule> groups) {
        this.groups = groups;
    }

    public List<Rule> getRules() {
        return rules;
    }

    public void setRules(List<Rule> rules) {
        this.rules = rules;
    }

    public List<GroupRule> getGroups() {
        return groups;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
