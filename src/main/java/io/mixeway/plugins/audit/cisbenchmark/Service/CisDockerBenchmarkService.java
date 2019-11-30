package io.mixeway.plugins.audit.cisbenchmark.Service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.pojo.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import io.mixeway.plugins.audit.cisbenchmark.model.CisBenchmarkProcesor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class CisDockerBenchmarkService {
    @Autowired
    ApiTypeRepository apiTypeRepository;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    ApiPermisionRepository apiPermisionRepository;
    @Autowired
    ActivityRepository activityRepository;
    @Autowired
    NodeAuditRepository nodeAuditRepository;
    @Autowired
    RequirementRepository requirementRepository;
    @Autowired
    NodeRepository nodeRepository;
    DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    LocalDateTime dateNow = LocalDateTime.now();

    private static final Logger log = LoggerFactory.getLogger(CisDockerBenchmarkService.class);
    CisBenchmarkProcesor procesor = new CisBenchmarkProcesor();


    public ResponseEntity<Status> getCisDocker(MultipartFile file, Long id) {
        ApiType apiType = apiTypeRepository.findByUrl(Constants.CIS_DOCKER_NAME);
        Project project = projectRepository.getOne(id);
        ApiPermision apiPermision = apiPermisionRepository.findByProjectAndApiType(project, apiType);
        if(apiPermision !=null && apiPermision.getEnabled()) {
            processReportDocker(apiType, project, file);
        }
        else
            log.warn("Project id {} has no permision to put api {}", id, Constants.API_TYPE_CIS_K8S);
        Activity act = new Activity();
        act.setInserted(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        act.setName("New audit results of: "+Constants.CIS_DOCKER_NAME+" for project: "+project.getName());
        activityRepository.save(act);
        return new ResponseEntity<Status>(new Status("OK"), HttpStatus.OK);
    }
    private void processReportDocker(ApiType apiType, Project project, MultipartFile file) {
        log.info("Putting CIS docker benchmark for project {} node {}",project.getName(), file.getOriginalFilename());
        BufferedReader br;
        List<String> result = new ArrayList<>();
        String nodeName = file.getOriginalFilename().substring(0,  file.getOriginalFilename().length()-4);
        String categoryname ="";
        Boolean process = false;
        Node node = null;
        try {
            String line;
            InputStream is = file.getInputStream();
            br = new BufferedReader(new InputStreamReader(is));
            int i=0;
            while ((line = br.readLine()) != null) {
                if ( checkIntegrityDocker(line)) {
                    process = true;
                }
                if(process) {
                    for (Map.Entry<String,Pattern> pattern : procesor.patterns.entrySet()) {
                        Matcher matcher = pattern.getValue().matcher(line);
                        if (matcher.matches()) {
                            if (pattern.getKey().equals(procesor.NODETYPE)) {
                                node = nodeRepository.findByProjectAndNameAndType(project,nodeName, "Docker");
                                if (node == null) {
                                    node = procesor.createNode(nodeName,Constants.CIS_DOCKER_NODE_NAME, project);
                                    nodeRepository.save(node);
                                }
                            } else if (pattern.getKey().equals(procesor.CATEGORY)) {
                                categoryname = matcher.group(3);
                            } else if (pattern.getKey().equals(procesor.REQUIREMENT)) {
                                if(!matcher.group(1).equals("INFO")) {
                                    Requirement requirement = requirementRepository.findByCode(matcher.group(2));
                                    if (requirement == null) {
                                        requirement = procesor.createRequirement(matcher.group(2),matcher.group(3));
                                        requirementRepository.save(requirement);
                                    }
                                    NodeAudit nodeAudit = nodeAuditRepository.findByRequirementAndNodeAndType(requirement, node,apiType);
                                    if (nodeAudit == null) {
                                        try {
                                            nodeAudit = procesor.createNodeAudit(node,apiType,requirement,
                                                    matcher.group(1),dateNow.format(dateFormatter).toString());
                                        } catch (Exception e) {
                                            log.error("Error during processing K8S CIS benchmark - {}, filename {}",e.getLocalizedMessage(),file.getOriginalFilename());
                                        }
                                        nodeAuditRepository.save(nodeAudit);
                                    } else {
                                        nodeAudit = procesor.updateNodeAudit(nodeAudit, matcher.group(1),
                                                dateNow.format(dateFormatter).toString());
                                        nodeAuditRepository.save(nodeAudit);
                                    }
                                }

                            } else
                                break;
                        }
                    }
                }
                i++;
            }
            if (!process)
                log.error("No proper file detected, ignoring..");

        } catch (IOException e) {
            System.err.println(e.getMessage());
        }

    }

    private boolean checkIntegrityDocker(String line) {
        if (line.contains("Initializing"))
            return true;
        else
            return false;
    }
}
