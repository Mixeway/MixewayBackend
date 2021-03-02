package io.mixeway.rest.dashboard.service;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.project.CreateProjectService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.rest.dashboard.model.SearchRequest;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import io.mixeway.rest.model.Projects;
import io.mixeway.rest.model.SourceDetectionChartData;
import io.mixeway.rest.model.VulnResponse;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.rest.dashboard.model.SearchResponse;
import io.mixeway.rest.dashboard.model.SessionOwner;

import javax.persistence.EntityNotFoundException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
@Service
public class DashboardService {
    private final CreateProjectService createProjectService;
    private final VulnHistoryRepository vulnHistoryRepository;
    private final ProjectRepository projectRepository;
    private final UserRepository userRepository;
    private final InterfaceRepository interfaceRepository;
    private final WebAppRepository webAppRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final PermissionFactory permissionFactory;
    private final VulnTemplate vulnTemplate;

    DashboardService(VulnTemplate vulnTemplate,
                     CodeProjectRepository codeProjectRepository, WebAppRepository webAppRepository, InterfaceRepository interfaceRepository,
                     UserRepository userRepository, ProjectRepository projectRepository, VulnHistoryRepository vulnHistoryRepository,
                     CreateProjectService createProjectService,PermissionFactory permissionFactory){
        this.createProjectService = createProjectService;
        this.userRepository = userRepository;
        this.permissionFactory = permissionFactory;
        this.projectRepository = projectRepository;
        this.vulnHistoryRepository = vulnHistoryRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.webAppRepository = webAppRepository;
        this.interfaceRepository = interfaceRepository;
        this.vulnTemplate = vulnTemplate;
    }

    private static final Logger log = LoggerFactory.getLogger(DashboardService.class);
    public List<OverAllVulnTrendChartData> getVulnTrendData(Principal principal) {

        return vulnHistoryRepository.getOverallVulnTrendData(permissionFactory.getProjectForPrincipal(principal).stream().map(Project::getId).collect(Collectors.toList()));
    }
    public SourceDetectionChartData getSourceTrendData(Principal principal) {

        return vulnHistoryRepository.getSourceTrendChart(permissionFactory.getProjectForPrincipal(principal).stream().map(Project::getId).collect(Collectors.toList()));
    }
    public List<Projects> getProjects(Principal principal) {
        List<Projects> projects = new ArrayList<>();
        for (Project p : permissionFactory.getProjectForPrincipal(principal)){
            Projects projects1 = new Projects();
            projects1.setId(p.getId());
            projects1.setCiid(p.getCiid());
            projects1.setName(p.getName());
            projects1.setDescription(p.getDescription());
            projects1.setRisk(p.getRisk());
            projects1.setEnableVulnManage(p.isEnableVulnManage() ? 1 : 0 );
            projects.add(projects1);
        }
        return projects;
    }

    public ResponseEntity putProject(String projectName, String projectDescription, String ciid, int enableVulnManage, Principal principal) {
        if (!projectRepository.getProjectByName(projectName).isPresent() && createProjectService.putProject(projectName,projectDescription,ciid, enableVulnManage, principal)){
            log.info("{} - Created new project {}",principal.getName(), LogUtil.prepare(projectName));
            return new ResponseEntity(HttpStatus.CREATED);
        } else {
            return new ResponseEntity(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity patchProject(Long projectId, Projects projectObject, Principal principal) {
        Optional<Project> project = projectRepository.findById(projectId);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get()) && ( project.get().getName().equals(projectObject.getName()) || !projectRepository.findByName(projectObject.getName()).isPresent())){
            String oldName = project.get().getName();
            project.get().setName(projectObject.getName());
            project.get().setDescription(projectObject.getDescription());
            project.get().setCiid(projectObject.getCiid());
            project.get().setEnableVulnManage(projectObject.getEnableVulnManage() == 1);
            log.info("{} - Updated project {}, new name is {}", principal.getName(), oldName,project.get().getName());
            projectRepository.save(project.get());
        } else {
            return new ResponseEntity(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity(HttpStatus.OK);
    }

    public ResponseEntity deleteProject(Long projectId, Principal principal) {
        Optional<Project> project = projectRepository.findById(projectId);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get()))
            try {
                projectRepository.delete(project.get());
                log.info("{} - Deleted project {}", principal.getName(), project.get().getName());
                return new ResponseEntity(HttpStatus.OK);
            } catch (Exception e){
                log.warn("Exception during delete project try, error is {}", e.getLocalizedMessage());
            }
        return new ResponseEntity(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<SessionOwner> getSessionOwner(String name) {
        Optional<User> user = userRepository.findByUsernameOrCommonName(name,name);
        if (user.isPresent()){
            return new ResponseEntity<>(new SessionOwner(name, user.get().getLogins()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
    }

    // TODO Permission handling
    public ResponseEntity<SearchResponse> search(SearchRequest searchRequest) {
        if ( searchRequest.getSearch().length() >5 ) {
            //SearchResponse searchResponse = new SearchResponse();
            //searchResponse.setAssets(interfaceRepository.searchForIp(searchRequest.getSearch()));
            //searchResponse.setCodeProjects(codeProjectRepository.searchForName(searchRequest.getSearch()));
            //searchResponse.setWebApps(webAppRepository.searchForUrl(searchRequest.getSearch()));
            //searchResponse.setVulns(setVulnsForVulnName(searchRequest.getSearch()));
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.OK);
        }
    }

    private List<VulnResponse> setVulnsForVulnName(String search) {
        List<VulnResponse> vulns = new ArrayList<>();
        List<ProjectVulnerability> vulnerabilities = vulnTemplate.projectVulnerabilityRepository
                .findTop100ByVulnerabilityIn(vulnTemplate.vulnerabilityRepository.findByNameContainingIgnoreCase(search));
        for (ProjectVulnerability pv : vulnerabilities){
            if (vulns.size() > 100)
                break;
            VulnResponse vuln = new VulnResponse();
            vuln.setLocation(pv.getLocation());
            vuln.setProjectId(pv.getProject().getId());
            vuln.setName(pv.getVulnerability().getName());
            vuln.setSource(pv.getVulnerabilitySource().getName());
            vulns.add(vuln);
        }
        return  vulns;
    }
}
