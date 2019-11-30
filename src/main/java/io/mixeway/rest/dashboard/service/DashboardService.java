package io.mixeway.rest.dashboard.service;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.project.CreateProjectService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.rest.dashboard.model.SearchRequest;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import io.mixeway.rest.model.Projects;
import io.mixeway.rest.model.SourceDetectionChartData;
import io.mixeway.rest.model.VulnResponse;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
@Service
public class DashboardService {
    private final CreateProjectService createProjectService;
    private final FindProjectService findProjectService;
    private final VulnHistoryRepository vulnHistoryRepository;
    private final ProjectRepository projectRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final UserRepository userRepository;
    private final InterfaceRepository interfaceRepository;
    private final WebAppRepository webAppRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final WebAppVulnRepository webAppVulnRepository;
    private final CodeVulnRepository codeVulnRepository;
    private final InfrastructureVulnRepository infrastructureVulnRepository;

    @Autowired
    DashboardService(InfrastructureVulnRepository infrastructureVulnRepository, CodeVulnRepository codeVulnRepository, WebAppVulnRepository webAppVulnRepository,
                     CodeProjectRepository codeProjectRepository, WebAppRepository webAppRepository, InterfaceRepository interfaceRepository,
                     UserRepository userRepository, ProjectRiskAnalyzer projectRiskAnalyzer, ProjectRepository projectRepository, VulnHistoryRepository vulnHistoryRepository,
                     FindProjectService findProjectService, CreateProjectService createProjectService){
        this.createProjectService = createProjectService;
        this.findProjectService = findProjectService;
        this.userRepository = userRepository;
        this.projectRiskAnalyzer = projectRiskAnalyzer;
        this.projectRepository = projectRepository;
        this.vulnHistoryRepository = vulnHistoryRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.webAppRepository = webAppRepository;
        this.infrastructureVulnRepository = infrastructureVulnRepository;
        this.codeVulnRepository = codeVulnRepository;
        this.webAppVulnRepository = webAppVulnRepository;
        this.interfaceRepository = interfaceRepository;
    }

    private static final Logger log = LoggerFactory.getLogger(DashboardService.class);
    public List<OverAllVulnTrendChartData> getVulnTrendData() {

        return vulnHistoryRepository.getOverallVulnTrendData();
    }
    public SourceDetectionChartData getSourceTrendData() {

        return vulnHistoryRepository.getSourceTrendChart();
    }
    public List<Projects> getProjects() {
        List<Projects> projects = new ArrayList<>();
        for (Project p : projectRepository.findAll()){
            int risk = projectRiskAnalyzer.getProjectAuditRisk(p) +
                    projectRiskAnalyzer.getProjectInfraRisk(p) +
                    projectRiskAnalyzer.getProjectCodeRisk(p) +
                    projectRiskAnalyzer.getProjectWebAppRisk(p);
            Projects projects1 = new Projects();
            projects1.setId(p.getId());
            projects1.setCiid(p.getCiid());
            projects1.setName(p.getName());
            projects1.setDescription(p.getDescription());
            projects1.setRisk(risk > 100 ? 100:risk);
            projects.add(projects1);
        }
        return projects;
    }

    public ResponseEntity putProject(String projectName, String projectDescription, String ciid, String user) {
        if (!projectRepository.findByName(projectName).isPresent() && createProjectService.putProject(projectName,projectDescription,ciid)){
            log.info("{} - Created new project {}", user, projectName);
            return new ResponseEntity(HttpStatus.CREATED);
        } else {
            return new ResponseEntity(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity patchProject(Long projectId, Projects projectObject, String user) {
        Optional<Project> project = projectRepository.findById(projectId);
        if (project.isPresent() && ( project.get().getName().equals(projectObject.getName()) || !projectRepository.findByName(projectObject.getName()).isPresent())){
            String oldName = project.get().getName();
            project.get().setName(projectObject.getName());
            project.get().setDescription(projectObject.getDescription());
            project.get().setCiid(projectObject.getCiid());
            log.info("{} - Updated project {}, new name is {}", user, oldName,project.get().getName());
            projectRepository.save(project.get());
        } else {
            return new ResponseEntity(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity(HttpStatus.OK);
    }

    public ResponseEntity deleteProject(Long projectId, String user) {
        Optional<Project> project = projectRepository.findById(projectId);
        if (project.isPresent())
            try {
                projectRepository.delete(project.get());
                log.info("{} - Deleted project {}", user, project.get().getName());
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
            return new ResponseEntity<>(null, HttpStatus.FORBIDDEN);
        }
    }

    public ResponseEntity<SearchResponse> search(SearchRequest searchRequest) {
        if ( searchRequest.getSearch().length() >5 ) {
            SearchResponse searchResponse = new SearchResponse();
            searchResponse.setAssets(interfaceRepository.searchForIp(searchRequest.getSearch()));
            searchResponse.setCodeProjects(codeProjectRepository.searchForName(searchRequest.getSearch()));
            searchResponse.setWebApps(webAppRepository.searchForUrl(searchRequest.getSearch()));
            searchResponse.setVulns(setVulnsForVulnName(searchRequest.getSearch()));
            return new ResponseEntity<>(searchResponse, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null, HttpStatus.OK);
        }
    }

    private List<VulnResponse> setVulnsForVulnName(String search) {
        List<VulnResponse> vulns = new ArrayList<>();
        for (CodeVuln cv : codeVulnRepository.searchForName(search)) {
            if (vulns.size() > 100)
                break;
            VulnResponse vuln = new VulnResponse();
            vuln.setLocation(cv.getCodeProject() != null ? cv.getCodeProject().getName() : cv.getCodeGroup().getName());
            vuln.setProjectId(cv.getCodeProject() != null ? cv.getCodeProject().getCodeGroup().getProject().getId() : cv.getCodeGroup().getProject().getId());
            vuln.setName(cv.getName());
            vuln.setSource("Source Code");
            vulns.add(vuln);
        }
        for (WebAppVuln wav : webAppVulnRepository.searchForName(search)){
            if (vulns.size() > 100)
                break;
            try {
                VulnResponse vuln = new VulnResponse();
                vuln.setLocation(wav.getLocation());
                vuln.setProjectId(wav.getWebApp().getProject().getId());
                vuln.setName(wav.getName());
                vuln.setSource("WebApplication DAST Scan");
                vulns.add(vuln);
            } catch (EntityNotFoundException e){

            }
        }
        for (InfrastructureVuln iv : infrastructureVulnRepository.searchForName(search)){
            if (vulns.size() > 100)
                break;
            try {
                VulnResponse vuln = new VulnResponse();
                vuln.setLocation(iv.getIntf().getPrivateip() + " (" + iv.getIntf().getAsset().getName() + ")");
                vuln.setProjectId(iv.getIntf().getAsset().getProject().getId());
                vuln.setName(iv.getName());
                vuln.setSource("Infrastructure scan");
                vulns.add(vuln);
            } catch (EntityNotFoundException e){

            }
        }
        return  vulns;
    }
}
