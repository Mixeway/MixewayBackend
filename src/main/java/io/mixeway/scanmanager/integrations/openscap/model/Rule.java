/*
 * @created  2021-01-21 : 21:33
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.scanmanager.integrations.openscap.model;

import lombok.Getter;
import lombok.Setter;
import org.simpleframework.xml.Attribute;
import org.simpleframework.xml.Element;
import org.simpleframework.xml.Root;

@Getter
@Setter
@Root(strict = false, name = "Rule")
public class Rule {
    @Element
    String title;
    String description;
    @Attribute
    String id;
}
