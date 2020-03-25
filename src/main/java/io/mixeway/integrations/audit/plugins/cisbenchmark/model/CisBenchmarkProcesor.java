package io.mixeway.integrations.audit.plugins.cisbenchmark.model;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.NodeAuditRepository;
import io.mixeway.db.repository.RequirementRepository;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CisBenchmarkProcesor {
    private HashMap<String, Pattern> patterns = new HashMap<>();
    public static final Pattern PATTERN_FIRST_LEVEL = Pattern.compile(".*\\[(\\D+)].*\\s(\\d+)\\s+-\\s(.*)");
    private static final Pattern PATTERN_FIRST_LEVEL_AQUA = Pattern.compile("\\[(.*)] (\\d) (.*)");
    private static final Pattern PATTERN_SECOND_LEVEL = Pattern.compile(".*\\[(\\D+)].*\\s(\\d+.\\d+)\\s+-\\s(.*)");
    private static final Pattern PATTER_DOCKER = Pattern.compile(".*\\[(\\S+)].*(\\d+.\\d+). - (.*)");
    private static final Pattern PATTERN_AQUASCRIPT = Pattern.compile("\\[(.*)] (\\d+.\\d+.\\d+) (.*) \\(.*\\)");
    public static final String NODETYPE="nodetype";
    public static final String CATEGORY="category";
    public static final String REQUIREMENT="requirement";
    public static final String AQUA="aqua";
    public static final String NODETYPEAQUA = "nodeaqua";

    public CisBenchmarkProcesor(){
        patterns.put(NODETYPE, PATTERN_FIRST_LEVEL);
        patterns.put(CATEGORY, PATTERN_SECOND_LEVEL);
        patterns.put(REQUIREMENT, PATTER_DOCKER);
        patterns.put(AQUA, PATTERN_AQUASCRIPT);
        patterns.put(NODETYPEAQUA, PATTERN_FIRST_LEVEL_AQUA);
    }
    public HashMap<String, Pattern> getPatterns(){
        return this.patterns;
    }

    public NodeAudit createNodeAudit(Node node, ApiType apiType, Requirement requirement, String score, String date) throws Exception {
        if (node==null){
            throw new Exception("Cannot create NodeAudit, node is null");
        }
        NodeAudit nodeAudit = new NodeAudit();
        nodeAudit.setNode(node);
        nodeAudit.setType(apiType);
        nodeAudit.setRequirement(requirement);
        nodeAudit.setScore(score);
        nodeAudit.setUpdated(date);
        return nodeAudit;
    }
    public NodeAudit updateNodeAudit(NodeAudit nodeAudit, String score, String updated){
        nodeAudit.setScore(score);
        nodeAudit.setUpdated(updated);
        return nodeAudit;
    }
    public Requirement createRequirement(String code, String name){
        Requirement requirement = new Requirement();
        requirement.setCode(code);
        requirement.setName(name);
        return requirement;
    }
    public Node createNode(String name, String type, Project project){
        Node node = new Node();
        node.setName(name);
        node.setType(type);
        node.setProject(project);
        return node;
    }
    public void createRequirements(Matcher matcher, RequirementRepository requirementRepository,
                                   NodeAuditRepository nodeAuditRepository, Node node, ApiType apiType, LocalDateTime dateNow,
                                   DateTimeFormatter dateFormatter) throws Exception {
        if(!matcher.group(1).equals("INFO")) {
            Requirement requirement = requirementRepository.findByCode(matcher.group(2));
            if (requirement == null) {
                requirement = this.createRequirement(matcher.group(2), matcher.group(3));
                requirementRepository.save(requirement);
            }
            NodeAudit nodeAudit = nodeAuditRepository.findByRequirementAndNodeAndType(requirement, node,apiType);
            if (nodeAudit == null) {
                nodeAudit = this.createNodeAudit(node,apiType,requirement, matcher.group(1),
                        dateNow.format(dateFormatter));
                nodeAuditRepository.save(nodeAudit);
            } else {
                nodeAudit = this.updateNodeAudit(nodeAudit,matcher.group(1),
                        dateNow.format(dateFormatter));
                nodeAuditRepository.save(nodeAudit);
            }
        }
    }
}
