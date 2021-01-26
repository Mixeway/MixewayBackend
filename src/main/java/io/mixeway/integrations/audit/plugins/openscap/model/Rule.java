/*
 * @created  2021-01-21 : 21:33
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.integrations.audit.plugins.openscap.model;

import org.simpleframework.xml.*;

@Root(strict = false, name = "Rule")
public class Rule {
    @Element
    String title;
    String description;
    @Attribute
    String id;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }
}
