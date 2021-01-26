/*
 * @created  2021-01-21 : 23:17
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.integrations.audit.plugins.openscap.model;

import org.simpleframework.xml.Element;
import org.simpleframework.xml.ElementList;
import org.simpleframework.xml.Root;

import java.util.List;

@Root(strict = false)
public class TestResult {
    @Element(required = false)
    String title;
    @ElementList(entry = "rule-result",data = true,inline = true)
    List<RuleResult> ruleResults;

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public List<RuleResult> getRuleResults() {
        return ruleResults;
    }

    public void setRuleResults(List<RuleResult> ruleResults) {
        this.ruleResults = ruleResults;
    }
}
