/*
 * @created  2021-01-21 : 21:43
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.scanmanager.integrations.openscap.model;

import org.simpleframework.xml.Path;
import org.simpleframework.xml.Root;
import org.simpleframework.xml.Text;

@Root(strict = false, name = "description")
public class RuleDescription {
    @Text(required = false)
    @Path("p")
    String description;
}
