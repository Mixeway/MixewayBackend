/*
 * @created  2021-01-21 : 20:31
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.scanmanager.integrations.openscap.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.simpleframework.xml.Element;
import org.simpleframework.xml.ElementList;
import org.simpleframework.xml.Root;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
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
}
