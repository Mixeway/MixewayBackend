/*
 * @created  2021-01-21 : 23:19
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
@Root(strict = false)
public class RuleResult {
    @Attribute(name = "idref")
    String idref;
    @Element(required = false)
    String result;
}
