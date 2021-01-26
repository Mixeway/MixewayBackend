/*
 * @created  2021-01-26 : 08:51
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.integrations.audit.plugins.openscap;

import io.mixeway.db.entity.CisRequirement;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.domain.service.vulnerability.CreateOrGetCisRequirementService;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.audit.plugins.openscap.model.*;
import org.simpleframework.xml.Serializer;
import org.simpleframework.xml.core.Persister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class OpenScapService {
    private static final Logger log = LoggerFactory.getLogger(OpenScapService.class);
    private final VulnTemplate vulnTemplate;
    private final CreateOrGetCisRequirementService createOrGetCisRequirementService;

    public OpenScapService(VulnTemplate vulnTemplate, CreateOrGetCisRequirementService createOrGetCisRequirementService){
        this.vulnTemplate = vulnTemplate;
        this.createOrGetCisRequirementService = createOrGetCisRequirementService;
    }

    /**
     * Loading report from openscap to database
     *
     * @param anInterface to link report with an asset
     * @param file file with report
     * @throws IOException
     */
    public void loadOpenScapReport(Interface anInterface, MultipartFile file) throws Exception {
        Serializer serializer = new Persister();
        Benchmark benchmark = serializer.read(Benchmark.class, file.getInputStream());
        log.info("[Openscap] Loading report for {} scope: {}", anInterface.getPrivateip(), benchmark.getTitle());
        HashMap<Rule, CisRequirement> benchmarkRules = loadBechmarkRules(benchmark);
        List<ProjectVulnerability> projectVulnerabilities = processVulnerabilitiesFromBenchmark(benchmark, benchmarkRules, anInterface);

    }

    /**
     * Creating project vulnerabilities from benchmark ruleresult
     * @param benchmark to process
     * @param benchmarkRules rules from report
     * @param anInterface to link result to
     */
    private List<ProjectVulnerability> processVulnerabilitiesFromBenchmark(Benchmark benchmark, HashMap<Rule, CisRequirement> benchmarkRules, Interface anInterface) {
        List<ProjectVulnerability> projectVulnerabilities = new ArrayList<>();
        List<ProjectVulnerability> oldVulns = vulnTemplate.projectVulnerabilityRepository.findByAnInterfaceAndVulnerabilitySource(anInterface, vulnTemplate.SOURCE_CISBENCHMARK);
        for (RuleResult ruleResult : benchmark.getTestResult().getRuleResults()){
            String ruleRef = ruleResult.getIdref();
            Rule rule = (Rule) benchmarkRules
                    .entrySet()
                    .stream()
                    .filter(entry -> entry.getKey().getId().equals(ruleRef))
                    .map(Map.Entry::getKey).findFirst().get();
            CisRequirement cisRequirement =(CisRequirement) benchmarkRules
                    .entrySet()
                    .stream()
                    .filter(entry -> entry.getKey().getId().equals(ruleRef))
                    .map(Map.Entry::getValue).findFirst().get();
            ProjectVulnerability projectVulnerability = new ProjectVulnerability(anInterface,null,null,rule.getDescription(),null,
                    "High",null,null,null, vulnTemplate.SOURCE_CISBENCHMARK, cisRequirement );

            projectVulnerabilities.add(projectVulnerability);

        }
        vulnTemplate.vulnerabilityPersistList(oldVulns, projectVulnerabilities);


        return projectVulnerabilities;
    }

    /**
     * Loading rules from benchmark into list
     * @param benchmark file to processs
     */
    private HashMap<Rule, CisRequirement> loadBechmarkRules(Benchmark benchmark) {
        HashMap<Rule, CisRequirement> requirementHashMap = new HashMap<>();
        for (Group types: benchmark.getGroups()){
            if (types.getGroups() != null){
                for (GroupRule requirements: types.getGroups()){
                    for (Rule rule : requirements.getRules()){
                        rule.setDescription(types.getTitle()+"\n"+requirements.getTitle()+"\n");
                        requirementHashMap.put(rule, createOrGetCisRequirementService.createOrGetCisRequirement(rule.getTitle(), benchmark.getTitle()));
                    }
                }
            } else {
                for (Rule rule : types.getRules()){
                    rule.setDescription(types.getTitle()+"\n");
                    requirementHashMap.put(rule, createOrGetCisRequirementService.createOrGetCisRequirement(rule.getTitle(), benchmark.getTitle()));
                }
            }
        }
        return requirementHashMap;
    }
}
