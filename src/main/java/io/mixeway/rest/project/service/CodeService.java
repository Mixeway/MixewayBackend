package io.mixeway.rest.project.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.*;
import io.mixeway.integrations.opensourcescan.model.Projects;
import io.mixeway.integrations.codescan.service.CodeScanService;
import io.mixeway.integrations.opensourcescan.service.OpenSourceScanService;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.project.model.*;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeVuln;
import io.mixeway.pojo.Status;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class CodeService {
    private static final Logger log = LoggerFactory.getLogger(CodeService.class);
    private final ProjectRepository projectRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final CodeGroupRepository codeGroupRepository;
    private final VaultHelper vaultHelper;
    private final CodeVulnRepository codeVulnRepository;
    private final PermissionFactory permissionFactory;
    private final CodeScanService codeScanService;
    private final OpenSourceScanService openSourceScanService;

    CodeService(ProjectRepository projectRepository, CodeProjectRepository codeProjectRepository, CodeGroupRepository codeGroupRepository,
                VaultHelper vaultHelper, CodeVulnRepository codeVulnRepository, PermissionFactory permissionFactory,
                CodeScanService  codeScanService, OpenSourceScanService openSourceScanService) {
        this.projectRepository = projectRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.vaultHelper = vaultHelper;
        this.codeGroupRepository = codeGroupRepository;
        this.codeVulnRepository = codeVulnRepository;
        this.permissionFactory = permissionFactory;
        this.openSourceScanService = openSourceScanService;
        this.codeScanService = codeScanService;
    }

    public ResponseEntity<CodeCard> showCodeRepos(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if ( project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            CodeCard codeCard = new CodeCard();
            codeCard.setCodeAutoScan(project.get().isAutoCodeScan());
            List<CodeModel> codeModels = new ArrayList<>();
            for (CodeProject cp : codeProjectRepository.findByCodeGroupIn(project.get().getCodes())){
                CodeModel codeModel = new CodeModel();
                codeModel.setVersionId(cp.getCodeGroup().getVersionIdAll());
                codeModel.setCodeProject(cp.getName());
                codeModel.setCodeGroup(cp.getCodeGroup().getName());
                codeModel.setBranch(cp.getBranch());
                codeModel.setId(cp.getId());
                codeModel.setdTrackUuid(cp.getdTrackUuid());
                codeModel.setRunning(cp.getCodeGroup().isRunning());
                codeModel.setRisk(cp.getRisk());
                codeModels.add(codeModel);
            }
            codeCard.setCodeModels(codeModels);
            return new ResponseEntity<>(codeCard, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<List<CodeGroup>> showCodeGroups(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            return new ResponseEntity<>(new ArrayList<>(project.get().getCodes()),HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<Status> saveCodeGroup(Long id, CodeGroupPutModel codeGroupPutModel, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            CodeGroup codeGroup = new CodeGroup();
            codeGroup.setBasePath("");
            codeGroup.setName(codeGroupPutModel.getCodeGroupName());
            codeGroup.setRepoUrl(codeGroupPutModel.getGiturl());
            codeGroup.setRepoUsername(codeGroupPutModel.getGitusername());
            codeGroup.setTechnique(codeGroupPutModel.getTech());
            codeGroup.setHasProjects(codeGroupPutModel.isChilds());
            codeGroup.setAuto(codeGroupPutModel.isAutoScan());
            codeGroup.setVersionIdAll(codeGroupPutModel.getVersionIdAll());
            codeGroup.setVersionIdsingle(codeGroupPutModel.getVersionIdSingle());
            codeGroup.setProject(project.get());
            codeGroupRepository.save(codeGroup);
            if (!codeGroup.getHasProjects()) {
                codeGroup.setVersionIdsingle(codeGroupPutModel.getVersionIdAll());
                createProjectForCodeGroup(codeGroup, codeGroupPutModel);
            }
            String uuidToken = UUID.randomUUID().toString();
            if (vaultHelper.savePassword(codeGroupPutModel.getGitpassword(), uuidToken)) {
                codeGroup.setRepoPassword(uuidToken);
            } else {
                codeGroup.setRepoPassword(codeGroupPutModel.getGitpassword());
            }
            codeGroupRepository.save(codeGroup);
            log.info("{} - Created new CodeGroup [{}] {}", username, project.get().getName(), codeGroup.getName());
            return new ResponseEntity<>(null,HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    private void createProjectForCodeGroup(CodeGroup codeGroup, CodeGroupPutModel codeGroupPutModel) {
        CodeProject cp = new CodeProject();
        cp.setName(codeGroup.getName());
        cp.setCodeGroup(codeGroup);
        cp.setBranch(Constants.CODE_DEFAULT_BRANCH);
        cp.setRepoUrl(codeGroup.getRepoUrl());
        cp.setRepoPassword(codeGroup.getRepoPassword());
        cp.setRepoUsername(codeGroup.getRepoUsername());
        cp.setTechnique(codeGroup.getTechnique());
        cp.setInQueue(false);
        cp.setdTrackUuid(codeGroupPutModel.getdTrackUuid());
        codeProjectRepository.save(cp);
    }

    public ResponseEntity<Status> saveCodeProject(Long id, CodeProjectPutModel codeProjectPutModel, String username) {
        Optional<Project> project = projectRepository.findById(id);
        Optional<CodeGroup> codeGroup = codeGroupRepository.findById(codeProjectPutModel.getCodeGroup());
        if (project.isPresent() && codeGroup.isPresent() && codeGroup.get().getProject().getId().equals(project.get().getId())){
            CodeProject codeProject = new CodeProject();
            codeProject.setCodeGroup(codeGroup.get());
            codeProject.setName(codeProjectPutModel.getCodeProjectName());
            codeProject.setSkipAllScan(false);
            codeProject.setdTrackUuid(codeProjectPutModel.getdTrackUuid());
            codeProject.setBranch(codeProjectPutModel.getBranch()!=null && !codeProjectPutModel.getBranch().equals("") ? codeProjectPutModel.getBranch() : Constants.CODE_DEFAULT_BRANCH);
            codeProject.setAdditionalPath(codeProjectPutModel.getAdditionalPath());
            codeProject.setRepoUrl(codeProjectPutModel.getProjectGiturl());
            codeProject.setTechnique(codeProjectPutModel.getProjectTech());
            codeProjectRepository.save(codeProject);
            log.info("{} - Created new CodeProject [{} / {} ] {}", username, project.get().getName(), codeGroup.get().getName(), codeProject.getName());
            return new ResponseEntity<>(null,HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> runSelectedCodeProjects(Long id, List<RunScanForCodeProject> runScanForCodeProjects, String username) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeScanService.codescanrunSelectedCodeProjectsScan(id, runScanForCodeProjects, username);
    }

    public ResponseEntity<Status> enableAutoScanForCodeProjects(Long id, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            for (CodeGroup codeGroup : project.get().getCodes()){
                codeGroup.setAuto(true);
                codeGroupRepository.save(codeGroup);
            }
            project.get().setAutoCodeScan(true);
            projectRepository.save(project.get());
            log.info("{} - Enabled auto SAST scan for {}", username, project.get().getName());
            return new ResponseEntity<>(null,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> runSingleCodeProjectScan(Long codeProjectId, String username) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        boolean putToQueue = codeScanService.putCodeProjectToQueue(codeProjectId);
        if (putToQueue){
            log.info("{} - Run SAST scan for {} - scope single", LogUtil.prepare(username), LogUtil.prepare(codeProjectId.toString()));
            return new ResponseEntity<>(null, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null, HttpStatus.EXPECTATION_FAILED);
        } }

    @Transactional
    public ResponseEntity<Status> deleteCodeProject(Long codeProjectId, String name) {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(codeProjectId);
        if (codeProject.isPresent()){
            codeProjectRepository.removeCodeGroup(codeProject.get().getId());
            log.info("{} - Deleted codeproject [{}] {}", name, codeProject.get().getCodeGroup().getProject().getName(), codeProject.get().getName());
            return new ResponseEntity<>(null,HttpStatus.OK);
        }
        return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
    }
    @Transactional
    public ResponseEntity<List<CodeVuln>> showCodeVulns(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            List<CodeVuln> codeVulns;
            try(Stream<CodeVuln> vulns = codeVulnRepository.findByCodeGroupInAndAnalysisNot(project.get().getCodes(),"Not an Issue")){
                codeVulns = vulns.collect(Collectors.toList());
            }
            return new ResponseEntity<>(codeVulns,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> disableAutoScanForCodeProjects(Long id, String name) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            for (CodeGroup codeGroup : project.get().getCodes()){
                codeGroup.setAuto(false);
                codeGroupRepository.save(codeGroup);
            }
            project.get().setAutoCodeScan(false);
            projectRepository.save(project.get());
            log.info("{} - Disabled auto SAST scan for {}", name, project.get().getName());
            return new ResponseEntity<>(null,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> editCodeProject(Long id, EditCodeProjectModel editCodeProjectModel, String name) {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(id);
        try{
            if (codeProject.isPresent() ){
                if ((editCodeProjectModel.getdTrackUuid() != null && !editCodeProjectModel.getdTrackUuid().equals(""))) {
                    UUID uuid = UUID.fromString(editCodeProjectModel.getdTrackUuid());
                    codeProject.get().setdTrackUuid(editCodeProjectModel.getdTrackUuid());
                    codeProjectRepository.save(codeProject.get());
                    log.info("{} Successfully Edited codeProject {}", name, codeProject.get().getName());
                }
                if (editCodeProjectModel.getSastProject() > 0) {
                    codeProject.get().getCodeGroup().setVersionIdAll(editCodeProjectModel.getSastProject());
                    if (!codeProject.get().getCodeGroup().getHasProjects()){
                        codeProject.get().getCodeGroup().setVersionIdsingle(editCodeProjectModel.getSastProject());
                    }
                    codeGroupRepository.save(codeProject.get().getCodeGroup());
                    log.info("{} Successfully Edited codeProject {}", name, codeProject.get().getName());
                }
                if (editCodeProjectModel.getBranch().equals("") || editCodeProjectModel.getBranch() == null){
                    codeProject.get().setBranch(Constants.CODE_PROJECT_DEFAULT_BRANCH);
                    log.warn("{} passed null branch for {}, setting to default {}", name, codeProject.get().getName(), Constants.CODE_PROJECT_DEFAULT_BRANCH);
                } else {
                    codeProject.get().setBranch(editCodeProjectModel.getBranch());
                    log.info("{} Setting branch for {} - {}", name, codeProject.get().getName(), LogUtil.prepare(editCodeProjectModel.getBranch()));
                }
                codeProjectRepository.save(codeProject.get());
                return new ResponseEntity<>(HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } catch (IllegalArgumentException | NullPointerException exception){
            log.warn("{} failed to edit codeProject {} due to wrong UUID format", name, id);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity<Status> createDTrackProject(Long id, String name) {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(id);
        try{
            if (codeProject.isPresent() && openSourceScanService.createProjectOnOpenSourceScanner(codeProject.get()) ) {

                log.info("{} Successfully Created dTrack Project {}", name, codeProject.get().getName());
                return new ResponseEntity<>(HttpStatus.OK);

            }
        } catch (IllegalArgumentException |IOException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException | KeyManagementException exception){
            log.warn("{} failed to create dTrackProject {} due to wrong UUID format", name, id);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity<List<Projects>> getdTracksProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return new ResponseEntity<>(openSourceScanService.getOpenSourceProjectFromScanner(), HttpStatus.OK);
    }

    public ResponseEntity<List<SASTProject>> getCodeProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
       return codeScanService.getProjectFromSASTScanner();
    }

    public ResponseEntity<Status> createRemoteProject(Long id, Long projectId) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        return codeScanService.createProjectOnSASTScanner(id, projectId);
    }

    public ResponseEntity<OpenSourceConfig> getOpenSourceConfig(Long id, String codeGroup, String codeProject) {
        return openSourceScanService.getOpenSourceScannerConfiguration(id, codeGroup, codeProject);
    }
}
