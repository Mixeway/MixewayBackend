package io.mixeway.integrations.audit.plugins.cisbenchmark.Service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import io.mixeway.integrations.audit.plugins.cisbenchmark.model.CisBenchmarkProcesor;

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
public class CisK8sBenchmarkService {
    private final ApiTypeRepository apiTypeRepository;
    private final ProjectRepository projectRepository;
    private final ApiPermisionRepository apiPermisionRepository;
    private final ActivityRepository activityRepository;
    private final NodeAuditRepository nodeAuditRepository;
    private final RequirementRepository requirementRepository;
    private final NodeRepository nodeRepository;

    CisK8sBenchmarkService(ApiTypeRepository apiTypeRepository, ProjectRepository projectRepository, ApiPermisionRepository apiPermisionRepository,
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
    private final DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private final LocalDateTime dateNow = LocalDateTime.now();
    private final CisBenchmarkProcesor procesor = new CisBenchmarkProcesor();
    private static final Logger log = LoggerFactory.getLogger(CisK8sBenchmarkService.class);

    public ResponseEntity<Status> processK8sReport(MultipartFile file, Long id) {
        ApiType apiType = apiTypeRepository.findByUrl(Constants.API_TYPE_CIS_K8S);
        Project project = projectRepository.getOne(id);
        ApiPermision apiPermision = apiPermisionRepository.findByProjectAndApiType(project, apiType);
        if(apiPermision !=null && apiPermision.getEnabled()) {
            processReportK8s(apiType, project, file);
        }
        else
            log.warn("Project id {} has no permision to put api {}", id, Constants.API_TYPE_CIS_K8S);
        Activity act = new Activity();
        act.setInserted(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        act.setName("New audit results of: "+Constants.API_TYPE_CIS_K8S+" for project: "+project.getName());
        activityRepository.save(act);
        return new ResponseEntity<>(new Status("OK"), HttpStatus.OK);
    }
    private void processReportK8s(ApiType apiType, Project project, MultipartFile file) {
        BufferedReader br;
        String filename;
        try {
            String nodeName = Objects.requireNonNull(file.getOriginalFilename()).split("-")[0];
            filename = file.getOriginalFilename().replace(nodeName + "-", "");
            filename = filename.substring(0, filename.length() - 4);
        } catch (NullPointerException ex){
            log.error("Nullpointer during cis k8s split for filename {}", file.getOriginalFilename());
            filename = file.getOriginalFilename();
        }
        log.info("Putting K8S docker benchmark for project {} node {}",project.getName(), LogUtil.prepare(Objects.requireNonNull(file.getOriginalFilename())));
        boolean process = false;
        Node node = null;
        try {
            String line;
            InputStream is = file.getInputStream();
            br = new BufferedReader(new InputStreamReader(is));
            int i=0;
            while ((line = br.readLine()) != null) {
                process = true;
                node = processDevOpsScriptFile(project,filename,node, apiType,line);
                i++;
                if (i > 1000)
                    break;
            }
            if (!process)
                log.error("No proper file detected, ignoring..");

        } catch (IOException e) {
            System.err.println(e.getMessage());
        }

    }
    private Node processDevOpsScriptFile(Project project, String filename, Node node, ApiType apiType, String line){
        for (Map.Entry<String,Pattern> pattern : procesor.getPatterns().entrySet()) {
            Matcher matcher = pattern.getValue().matcher(line);
            if (matcher.matches()) {
                if (pattern.getKey().equals(CisBenchmarkProcesor.NODETYPE) || pattern.getKey().equals(CisBenchmarkProcesor.NODETYPEAQUA)) {
                    node = nodeRepository.findByProjectAndNameAndType(project,filename, matcher.group(3));
                    if (node == null) {
                        node = procesor.createNode(filename,matcher.group(3),project);
                        nodeRepository.save(node);
                    }
                } else if (pattern.getKey().equals(CisBenchmarkProcesor.REQUIREMENT) || pattern.getKey().equals(CisBenchmarkProcesor.AQUA)) {
                    try {
                        procesor.createRequirements(matcher, requirementRepository,
                                nodeAuditRepository, node, apiType, dateNow,
                                dateFormatter);

                    } catch (Exception e) {
                        log.error("Error during processing K8S CIS benchmark - {}, filename {}",e.getLocalizedMessage(),filename);
                    }

                } else
                    break;
            }
        }
        return node;
    }

}
