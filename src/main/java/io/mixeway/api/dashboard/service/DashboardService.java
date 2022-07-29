package io.mixeway.api.dashboard.service;

import io.mixeway.api.dashboard.model.*;
import io.mixeway.api.project.model.EditCodeProjectModel;
import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.api.protocol.SourceDetectionChartData;
import io.mixeway.db.entity.*;
import io.mixeway.domain.service.asset.FindAssetService;
import io.mixeway.domain.service.asset.UpdateAssetService;
import io.mixeway.domain.service.project.CreateProjectService;
import io.mixeway.domain.service.project.DeleteProjectService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.UpdateProjectService;
import io.mixeway.domain.service.scan.GetScanNumberService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.UpdateCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.UpdateWebAppService;
import io.mixeway.domain.service.user.FindUserService;
import io.mixeway.domain.service.vulnhistory.FindVulnHistoryService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.utils.LogUtil;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Log4j2
@RequiredArgsConstructor
public class DashboardService {
    private final CreateProjectService createProjectService;
    private final PermissionFactory permissionFactory;
    private final VulnTemplate vulnTemplate;
    private final GetScanNumberService getScanNumberService;
    private final FindVulnHistoryService findVulnHistoryService;
    private final FindProjectService findProjectService;
    private final UpdateProjectService updateProjectService;
    private final DeleteProjectService deleteProjectService;
    private final FindUserService findUserService;
    private final FindCodeProjectService findCodeProjectService;
    private final FindWebAppService findWebAppService;
    private final FindAssetService findAssetService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final UpdateWebAppService updateWebAppService;
    private final UpdateAssetService updateAssetService;



    public List<OverAllVulnTrendChartData> getVulnTrendData(Principal principal) {

        return findVulnHistoryService.getVulnTrendData(principal);
    }
    public SourceDetectionChartData getSourceTrendData(Principal principal) {

        return findVulnHistoryService.getSourceTrendData(principal);
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

    public ResponseEntity<Status> putProject(String projectName, String projectDescription, String ciid, int enableVulnManage, Principal principal) {
        if (!findProjectService.getProjectByName(projectName).isPresent() && createProjectService.putProject(projectName,projectDescription,ciid, enableVulnManage, principal)){
            log.info("{} - Created new project {}",principal.getName(), LogUtil.prepare(projectName));
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> patchProject(Long projectId, Projects projectObject, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(projectId);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())
                && ( project.get().getName().equals(projectObject.getName())
                || !findProjectService.getProjectByName(projectObject.getName()).isPresent())){
            String oldName = project.get().getName();
            updateProjectService.update(project.get(), projectObject);
            log.info("{} - Updated project {}, new name is {}", principal.getName(), oldName,project.get().getName());
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }

    public ResponseEntity<Status> deleteProject(Long projectId, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(projectId);;
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get()))
            try {
                deleteProjectService.delete(project.get());
                log.info("[Dashboard] User {} - Deleted project {}", principal.getName(), project.get().getName());
                return new ResponseEntity<>(HttpStatus.OK);
            } catch (Exception e){
                log.warn("Exception during delete project try, error is {}", e.getLocalizedMessage());
            }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<SessionOwner> getSessionOwner(String name) {
        Optional<User> user = findUserService.findByUsernameOrCommonName(name,name);
        return user.map(value -> new ResponseEntity<>(new SessionOwner(name, value.getLogins()), HttpStatus.OK)).orElseGet(() -> new ResponseEntity<>(HttpStatus.FORBIDDEN));
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

    public ResponseEntity<DashboardTopStatistics> getRootStatistics(Principal principal) {
        DashboardTopStatistics dashboardTopStatistics = new DashboardTopStatistics();

        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.getLatestVulnerabilitiesForProjects(permissionFactory.getProjectForPrincipal(principal));

        StatisticCard statisticCard = new StatisticCard(
          findProjectService.count(),
          getScanNumberService.getNumberOfScansRunning(),
          getScanNumberService.getNumberOfScansInQueue(),
          vulnTemplate.projectVulnerabilityRepository.count()
        );
        dashboardTopStatistics.setStatisticCard(statisticCard);
        dashboardTopStatistics.setProjectVulnerabilityList(projectVulnerabilities.stream().limit(5).collect(Collectors.toList()));
        return new ResponseEntity<>(dashboardTopStatistics, HttpStatus.OK);
    }

    /**
     * Merging two projects. Move all resources in source project to destination project and delete source.
     * 1. Move all codeprojects
     * 2. move all assets
     * 3. move all webapps
     * 4. move all project vulnerabilities
     * 5. delete source project
     */
    public ResponseEntity<Status> mergeTwoProjects(long sourceId, long destinationId, Principal principal) {
        Optional<Project> sourceProject = findProjectService.findProjectById(sourceId);
        Optional<Project> destinationProject = findProjectService.findProjectById(destinationId);
        if (sourceProject.isPresent() && destinationProject.isPresent()) {
            // Loop over CodeProjects, change project_id
            updateCodeProjectService.changeProjectForCodeProject(sourceProject.get(), destinationProject.get());
            // Loop over Assets chamge project id
            updateAssetService.changeProjectForAssets(sourceProject.get(), destinationProject.get());
            // Loop over webapps chamge project id
            updateWebAppService.changeProjectForWebApps(sourceProject.get(), destinationProject.get());
            // Loop over project vulnerabilties chanage project id
            List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByProjectList(sourceProject.get().getId());
            for (ProjectVulnerability pv : projectVulnerabilities) {
                pv.setProject(destinationProject.get());
                vulnTemplate.projectVulnerabilityRepository.saveAndFlush(pv);
            }

            // delete source project
            this.deleteProject(sourceId, principal);
            log.info("[Dashboard] User {}, successfully merge project {} to project {}", principal.getName(), sourceProject.get().getName(), destinationProject.get().getName());
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

    }
}
