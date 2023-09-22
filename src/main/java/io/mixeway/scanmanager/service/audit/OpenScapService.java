/*
 * @created  2021-01-26 : 08:51
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.scanmanager.service.audit;

import io.mixeway.db.entity.CisRequirement;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.domain.service.vulnmanager.CreateOrGetCisRequirementService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.openscap.model.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.simpleframework.xml.Serializer;
import org.simpleframework.xml.core.Persister;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Log4j2
@RequiredArgsConstructor
public class OpenScapService {
    private final VulnTemplate vulnTemplate;
    private final CreateOrGetCisRequirementService createOrGetCisRequirementService;


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
        HashMap<Rule, CisRequirement> benchmarkRules = loadBechmarkRules(benchmark);
        log.info("[Openscap] Loading report for {} scope: {}, benchmark rules: {}", anInterface.getPrivateip(), benchmark.getTitle(), benchmarkRules.size());
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
                    "High",null,null,null, vulnTemplate.SOURCE_CISBENCHMARK, cisRequirement,null );

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
