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

@Root(strict = false,name = "Group")
public class GroupRule {
    @Element
    String title;
    @Element(required = false)
    String description;
    @ElementList(entry = "Rule", inline = true)
    List<Rule>rules;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<Rule> getRules() {
        return rules;
    }

    public void setRules(List<Rule> rules) {
        this.rules = rules;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

}
