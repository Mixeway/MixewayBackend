package io.mixeway.plugins.audit.cisbenchmark.Service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.Status;
import org.checkerframework.checker.units.qual.A;
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
    private final ApiTypeRepository apiTypeRepository;
    private final ProjectRepository projectRepository;
    private final ApiPermisionRepository apiPermisionRepository;
    private final ActivityRepository activityRepository;
    private final NodeAuditRepository nodeAuditRepository;
    private final RequirementRepository requirementRepository;
    private final NodeRepository nodeRepository;
    private DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private LocalDateTime dateNow = LocalDateTime.now();

    private static final Logger log = LoggerFactory.getLogger(CisDockerBenchmarkService.class);
    private CisBenchmarkProcesor procesor = new CisBenchmarkProcesor();

    @Autowired
    CisDockerBenchmarkService(ApiTypeRepository apiTypeRepository, ProjectRepository projectRepository, ApiPermisionRepository apiPermisionRepository,
                              ActivityRepository activityRepository, NodeAuditRepository nodeAuditRepository, RequirementRepository requirementRepository,
                              NodeRepository nodeRepository){
        this.apiPermisionRepository = apiPermisionRepository;
        this.projectRepository = projectRepository;
        this.apiTypeRepository =apiTypeRepository ;
        this.nodeAuditRepository = nodeAuditRepository;
        this.nodeRepository = nodeRepository;
        this.activityRepository = activityRepository;
        this.requirementRepository = requirementRepository;
    }



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
        return new ResponseEntity<>(new Status("OK"), HttpStatus.OK);
    }
    private void processReportDocker(ApiType apiType, Project project, MultipartFile file) {
        log.info("Putting CIS docker benchmark for project {} node {}",project.getName(), LogUtil.prepare(file.getOriginalFilename()));
        BufferedReader br;
        String nodeName = Objects.requireNonNull(file.getOriginalFilename()).substring(0,  file.getOriginalFilename().length()-4);
        boolean process = false;
        Node node = null;
        try {
            String line;
            InputStream is = file.getInputStream();
            br = new BufferedReader(new InputStreamReader(is));
            while ((line = br.readLine()) != null) {
                if ( checkIntegrityDocker(line)) {
                    process = true;
                }
                if(process) {
                    label:
                    for (Map.Entry<String, Pattern> pattern : procesor.getPatterns().entrySet()) {
                        Matcher matcher = pattern.getValue().matcher(line);
                        if (matcher.matches()) {
                            switch (pattern.getKey()) {
                                case CisBenchmarkProcesor.NODETYPE:
                                    node = nodeRepository.findByProjectAndNameAndType(project, nodeName, "Docker");
                                    if (node == null) {
                                        node = procesor.createNode(nodeName, Constants.CIS_DOCKER_NODE_NAME, project);
                                        nodeRepository.save(node);
                                    }
                                    break;
                                case CisBenchmarkProcesor.CATEGORY:
                                    break;
                                case CisBenchmarkProcesor.REQUIREMENT:
                                    if (!matcher.group(1).equals("INFO")) {
                                        Requirement requirement = requirementRepository.findByCode(matcher.group(2));
                                        if (requirement == null) {
                                            requirement = procesor.createRequirement(matcher.group(2), matcher.group(3));
                                            requirementRepository.save(requirement);
                                        }
                                        NodeAudit nodeAudit = nodeAuditRepository.findByRequirementAndNodeAndType(requirement, node, apiType);
                                        if (nodeAudit == null) {
                                            try {
                                                nodeAudit = procesor.createNodeAudit(node, apiType, requirement,
                                                        matcher.group(1), dateNow.format(dateFormatter));
                                            } catch (Exception e) {
                                                log.error("Error during processing K8S CIS benchmark - {}, filename {}", e.getLocalizedMessage(), file.getOriginalFilename());
                                            }
                                            assert nodeAudit != null;
                                            nodeAuditRepository.save(nodeAudit);
                                        } else {
                                            nodeAudit = procesor.updateNodeAudit(nodeAudit, matcher.group(1),
                                                    dateNow.format(dateFormatter));
                                            nodeAuditRepository.save(nodeAudit);
                                        }
                                    }

                                    break;
                                default:
                                    break label;
                            }
                        }
                    }
                }
            }
            if (!process)
                log.error("No proper file detected, ignoring..");

        } catch (IOException e) {
            System.err.println(e.getMessage());
        }

    }

    private boolean checkIntegrityDocker(String line) {
        return line.contains("Initializing");
    }
}
