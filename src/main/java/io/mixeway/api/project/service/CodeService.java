package io.mixeway.api.project.service;

import io.mixeway.api.project.model.*;
import io.mixeway.api.protocol.OpenSourceConfig;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.UpdateProjectService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.OperateOnCodeProject;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.model.Projects;
import io.mixeway.scanmanager.service.code.CodeScanService;
import io.mixeway.scanmanager.service.opensource.OpenSourceScanService;
import io.mixeway.utils.*;
import io.mixeway.utils.CodeGroupPutModel;
import io.mixeway.utils.RunScanForCodeProject;
import io.mixeway.utils.SASTProject;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.UnknownContentTypeException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@Log4j2
@RequiredArgsConstructor
public class CodeService {
    private final PermissionFactory permissionFactory;
    private final CodeScanService codeScanService;
    private final OpenSourceScanService openSourceScanService;
    private final VulnTemplate vulnTemplate;
    private final FindProjectService findProjectService;
    private final FindCodeProjectService findCodeProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final OperateOnCodeProject operateOnCodeProject;
    private final UpdateProjectService updateProjectService;

    public ResponseEntity<CodeCard> showCodeRepos(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if ( project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            CodeCard codeCard = new CodeCard();
            codeCard.setCodeAutoScan(project.get().isAutoCodeScan());
            List<CodeModel> codeModels = new ArrayList<>();
            for (CodeProject cp : findCodeProjectService.findByProject(project.get())) {
                CodeModel codeModel = CodeModel.builder()
                        .versionId(cp.getVersionIdAll())
                        .codeProject(cp.getName())
                        .branch(cp.getBranch())
                        .id(cp.getId())
                        .dTrackUuid(cp.getdTrackUuid())
                        .running(cp.getRunning())
                        .risk(cp.getRisk())
                        .repoUrl(cp.getRepoUrl())
                        .repoUsername(cp.getRepoUsername())
                        .repoPassword(StringUtils.isNoneBlank(cp.getRepoPassword()) ? Constants.DUMMY_PASSWORD : "")
                        .build();
                codeModels.add(codeModel);
            }
            codeCard.setCodeModels(codeModels);
            return new ResponseEntity<>(codeCard, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> saveCodeProject(Long id, CodeGroupPutModel codeGroupPutModel, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())){
            createOrGetCodeProjectService.createCodeProject(project.get(), codeGroupPutModel);
            log.info("{} - Created new CodeGroup [{}] {}", principal.getName(), project.get().getName(), codeGroupPutModel.getCodeGroupName());
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> saveCodeProject(Long id, CodeProjectPutModel codeProjectPutModel, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() &&
                permissionFactory.canUserAccessProject(principal,project.get())){
            createOrGetCodeProjectService.createCodeProject(project.get(), codeProjectPutModel);
            log.info("{} - Created new CodeProject [{} / {} ]", principal.getName(), project.get().getName(), codeProjectPutModel.getCodeProjectName());
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> runSelectedCodeProjects(Long id, List<RunScanForCodeProject> runScanForCodeProjects, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeScanService.codescanrunSelectedCodeProjectsScan(id, runScanForCodeProjects, principal);
    }

    public ResponseEntity<Status> enableAutoScanForCodeProjects(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            updateProjectService.enableCodeAutoScan(project.get());

            log.info("{} - Enabled auto SAST scan for {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> runSingleCodeProjectScan(Long codeProjectId, Principal principal) {
        boolean putToQueue = codeScanService.putCodeProjectToQueue(codeProjectId, principal);
        if (putToQueue){
            log.info("{} - Run SAST scan for {} - scope single", LogUtil.prepare(principal.getName()), LogUtil.prepare(codeProjectId.toString()));
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        } }

    @Transactional
    public ResponseEntity<Status> deleteCodeProject(Long codeProjectId, Principal principal) {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(codeProjectId);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())){
            log.info("{} - Deleted codeproject [{}] {}", principal.getName(), codeProject.get().getProject().getName(), codeProject.get().getName());
            operateOnCodeProject.deleteCodeProject(codeProject.get());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }
    @Transactional
    public ResponseEntity<List<ProjectVulnerability>> showCodeVulns(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            List<ProjectVulnerability> codeVulns;
            try(Stream<ProjectVulnerability> vulns = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectAndVulnerabilitySourceAndAnalysisNot(project.get(),vulnTemplate.SOURCE_SOURCECODE,"Not an Issue")){
                codeVulns = vulns.collect(Collectors.toList());
            }
            return new ResponseEntity<>(codeVulns,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> disableAutoScanForCodeProjects(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            updateProjectService.disableCodeAutoScan(project.get());
            log.info("{} - Disabled auto SAST scan for {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    private boolean editSCASettings(String uuid, CodeProject codeProject){
        if (codeProject.getdTrackUuid() == null && StringUtils.isNotBlank(uuid)){
            return true;
        } else if (codeProject.getdTrackUuid() == null && uuid == null){
            return false;
        } else {
            return codeProject.getProject() == null || !codeProject.getdTrackUuid().equals(uuid);
        }
    }
    public ResponseEntity<Status> editCodeProject(Long id, EditCodeProjectModel editCodeProjectModel, Principal principal) {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
        try{
            if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())){
                if (editSCASettings(editCodeProjectModel.getRemoteId(), codeProject.get())) {
                    operateOnCodeProject.setSCA(codeProject.get(),editCodeProjectModel);
                    log.info("{} Edited CodeProject {} scope SCA", principal.getName(), codeProject.get().getName());
                }
                if (editCodeProjectModel.getSastProject() > 0 && codeProject.get().getVersionIdAll() != editCodeProjectModel.getSastProject() ) {
                    codeProject.get().setVersionIdAll(editCodeProjectModel.getSastProject());
                    operateOnCodeProject.setVersionId(codeProject.get(), editCodeProjectModel);
                    log.info("{} Edited CodeProject {} scope SAST scanner integration", principal.getName(), codeProject.get().getName());
                }
                if (StringUtils.isNotBlank(editCodeProjectModel.getBranch()) && !codeProject.get().getBranch().equals(editCodeProjectModel.getBranch())){
                    operateOnCodeProject.setBranch(codeProject.get(), editCodeProjectModel.getBranch());
                    log.info("{} Edited CodeProject {} scope Branch, new value: {}", principal.getName(), codeProject.get().getName(), LogUtil.prepare(editCodeProjectModel.getBranch()));
                }
                if (StringUtils.isNotBlank(editCodeProjectModel.getRepoUrl()) && !codeProject.get().getRepoUrl().equals(editCodeProjectModel.getRepoUrl())){
                    operateOnCodeProject.setRepoUrl(codeProject.get(), editCodeProjectModel);
                    log.info("{} Edited CodeProject {} scope RepoURL, new value: {}", principal.getName(), codeProject.get().getName(), LogUtil.prepare(editCodeProjectModel.getRepoUrl()));

                }
                if (StringUtils.isNotBlank(editCodeProjectModel.getRepoUsername()) && !codeProject.get().getRepoUsername().equals(editCodeProjectModel.getRepoUsername())){
                    operateOnCodeProject.setRepoUsername(codeProject.get(), editCodeProjectModel);
                    log.info("{} Edited CodeProject {} scope RepoUsername, new value: {}", principal.getName(), codeProject.get().getName(), LogUtil.prepare(editCodeProjectModel.getRepoUsername()));

                }
                if (!editCodeProjectModel.getRepoPassword().equals(Constants.DUMMY_PASSWORD) && !editCodeProjectModel.getRepoPassword().equals(Constants.DUMMY_PASSWORD2)){
                    operateOnCodeProject.setRepoPassword(codeProject.get(), editCodeProjectModel);
                    log.info("{} Edited CodeProject {} scope Password", principal.getName(), codeProject.get().getName());
                }
                return new ResponseEntity<>(HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } catch (IllegalArgumentException | NullPointerException exception){
            exception.printStackTrace();
            log.warn("{} failed to edit codeProject {} due to wrong UUID format", principal.getName(), id);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity<Status> createDTrackProject(Long id, Principal principal) {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
        try{
            if (codeProject.isPresent() &&
                    permissionFactory.canUserAccessProject(principal, codeProject.get().getProject()) &&
                    openSourceScanService.createProjectOnOpenSourceScanner(codeProject.get()) ) {

                log.info("{} Successfully Created dTrack Project {}", principal.getName(), codeProject.get().getName());
                return new ResponseEntity<>(HttpStatus.OK);

            }
        } catch (IllegalArgumentException |IOException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException | KeyManagementException exception){
            log.warn("{} failed to create dTrackProject {} due to wrong UUID format", principal.getName(), id);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity<List<Projects>> getOpenSourceProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        try {
            return new ResponseEntity<>(openSourceScanService.getOpenSourceProjectFromScanner(), HttpStatus.OK);
        } catch (UnknownContentTypeException e){
            log.error("[API] Unable to load OpenSource projects");
            return new ResponseEntity<>(new ArrayList<>(), HttpStatus.OK);
        }
    }

    public ResponseEntity<List<SASTProject>> getCodeProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
       return codeScanService.getProjectFromSASTScanner();
    }

    public ResponseEntity<Status> createRemoteProject(Long id, Long projectId, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        return codeScanService.createProjectOnSASTScanner(id, projectId, principal);
    }

    public ResponseEntity<OpenSourceConfig> getOpenSourceConfig(Long id, String codeGroup, String codeProject, Principal principal) {
        return openSourceScanService.getOpenSourceScannerConfiguration(id, codeGroup, codeProject, principal);
    }

    public ResponseEntity<CodeProject> searchCodeProject(CodeProjectSearch search, Principal principal) {
        Optional<CodeProject> codeProject  = findCodeProjectService.findByRepoUrl(search.getRepourl());
        if(!codeProject.isPresent()){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        if(!permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())){
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        return new ResponseEntity<>(codeProject.get(), HttpStatus.OK);
    }
}
