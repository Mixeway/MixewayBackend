/*
 * @created  2021-01-21 : 23:17
 * @project  MixewayScanner
 * @author   siewer
 */
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
public class TestResult {
    @Element(required = false)
    String title;
    @ElementList(entry = "rule-result",data = true,inline = true)
    List<RuleResult> ruleResults;
}
