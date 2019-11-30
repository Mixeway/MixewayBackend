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
public class CisK8sBenchmarkService {
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
    private DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private LocalDateTime dateNow = LocalDateTime.now();
    private CisBenchmarkProcesor procesor = new CisBenchmarkProcesor();
    private static final Logger log = LoggerFactory.getLogger(CisK8sBenchmarkService.class);

    public ResponseEntity<Status> processK8sReport(MultipartFile file, Long id) throws IOException{
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
    private void processReportK8s(ApiType apiType, Project project, MultipartFile file) throws IOException{
        BufferedReader br;
        List<String> result = new ArrayList<>();
        String filename="";
        try {
            String nodeName = file.getOriginalFilename().split("-")[0];
            filename = file.getOriginalFilename().replace(nodeName + "-", "");
            filename = filename.substring(0, filename.length() - 4);
        } catch (NullPointerException ex){
            log.error("Nullpointer during cis k8s split for filename {}", file.getOriginalFilename());
            filename = file.getOriginalFilename();
        }
        log.info("Putting K8S docker benchmark for project {} node {}",project.getName(), file.getOriginalFilename());
        String categoryname ="";
        Boolean process = false;
        Node node = null;
        boolean aqua = checkIntegrityForAquaScript(file);
        try {
            String line;
            InputStream is = file.getInputStream();
            br = new BufferedReader(new InputStreamReader(is));
            int i=0;
            while ((line = br.readLine()) != null) {
                process = true;
                node = processDevOpsScriptFile(project,filename,node,categoryname,apiType,line);
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
    private Node processDevOpsScriptFile(Project project, String filename, Node node, String categoryname, ApiType apiType,String line){
        for (Map.Entry<String,Pattern> pattern : procesor.patterns.entrySet()) {
            Matcher matcher = pattern.getValue().matcher(line);
            if (matcher.matches()) {
                if (pattern.getKey().equals(procesor.NODETYPE) || pattern.getKey().equals(procesor.NODETYPEAQUA)) {
                    node = nodeRepository.findByProjectAndNameAndType(project,filename, matcher.group(3));
                    if (node == null) {
                        node = procesor.createNode(filename,matcher.group(3),project);
                        nodeRepository.save(node);
                    }
                } else if (pattern.getKey().equals(procesor.CATEGORY)) {
                    categoryname = matcher.group(3);
                } else if (pattern.getKey().equals(procesor.REQUIREMENT) || pattern.getKey().equals(procesor.AQUA)) {

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
    private boolean checkIntegrityForAquaScript(MultipartFile file) throws IOException{
        InputStream is = file.getInputStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        String line, lastline ="";
        while ((line = br.readLine()) != null) {
            lastline = line;
        }
        if (lastline.contains("checks INFO"))
            return true;
        else
            return false;
    }

    private boolean checkIntegrity(String line) {
        return procesor.PATTERN_FIRST_LEVEL.matcher(line).matches();
    }
}
