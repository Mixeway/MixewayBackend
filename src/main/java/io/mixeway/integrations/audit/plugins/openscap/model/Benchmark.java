/*
 * @created  2021-01-21 : 20:31
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.integrations.audit.plugins.openscap.model;

import org.simpleframework.xml.*;

import java.util.List;

@Root(strict = false, name = "Benchmark")
public class Benchmark {
    @Element
    String status;
    @Element
    String title;

    @ElementList(entry = "Group",data = true,inline = true)
    List<Group> groups;
    @Element(name = "TestResult")
    TestResult testResult;
    public List<Group> getGroups() {
        return groups;
    }

    public TestResult getTestResult() {
        return testResult;
    }

    public void setTestResult(TestResult testResult) {
        this.testResult = testResult;
    }

    public void setGroups(List<Group> groups) {
        this.groups = groups;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
