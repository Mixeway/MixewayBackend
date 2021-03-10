package io.mixeway.rest.project.service;

import com.amazonaws.services.ec2.model.PriceSchedule;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.opensourcescan.model.Projects;
import io.mixeway.integrations.codescan.service.CodeScanService;
import io.mixeway.integrations.opensourcescan.service.OpenSourceScanService;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.project.model.*;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import io.mixeway.pojo.Status;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class CodeService {
    private static final Logger log = LoggerFactory.getLogger(CodeService.class);
    private final ProjectRepository projectRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final CodeGroupRepository codeGroupRepository;
    private final VaultHelper vaultHelper;
    private final PermissionFactory permissionFactory;
    private final CodeScanService codeScanService;
    private final OpenSourceScanService openSourceScanService;
    private final VulnTemplate vulnTemplate;
    private final CxBranchRepository cxBranchRepository;

    CodeService(ProjectRepository projectRepository, CodeProjectRepository codeProjectRepository, CodeGroupRepository codeGroupRepository,
                VaultHelper vaultHelper, VulnTemplate vulnTemplate, PermissionFactory permissionFactory,
                CodeScanService  codeScanService, OpenSourceScanService openSourceScanService, CxBranchRepository cxBranchRepository) {
        this.projectRepository = projectRepository;
        this.cxBranchRepository = cxBranchRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.vaultHelper = vaultHelper;
        this.codeGroupRepository = codeGroupRepository;
        this.vulnTemplate = vulnTemplate;
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
                codeModel.setRepoUrl(cp.getRepoUrl());
                codeModel.setRepoUsername(cp.getRepoUsername());
                codeModel.setRepoPassword(StringUtils.isNoneBlank(cp.getRepoPassword()) ? Constants.DUMMY_PASSWORD : "");
                codeModels.add(codeModel);
            }
            codeCard.setCodeModels(codeModels);
            return new ResponseEntity<>(codeCard, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<List<CodeGroup>> showCodeGroups(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            return new ResponseEntity<>(new ArrayList<>(project.get().getCodes()),HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<Status> saveCodeGroup(Long id, CodeGroupPutModel codeGroupPutModel, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())){
            CodeGroup codeGroup = new CodeGroup();
            codeGroup.setBasePath("");
            codeGroup.setName(codeGroupPutModel.getCodeGroupName());
            codeGroup.setRepoUrl(setRepoUrl(codeGroupPutModel));
            codeGroup.setRepoUsername(codeGroupPutModel.getGitusername());
            codeGroup.setTechnique(codeGroupPutModel.getTech());
            codeGroup.setHasProjects(codeGroupPutModel.isChilds());
            codeGroup.setAuto(codeGroupPutModel.isAutoScan());
            codeGroup.setVersionIdAll(codeGroupPutModel.getVersionIdAll());
            codeGroup.setVersionIdsingle(codeGroupPutModel.getVersionIdSingle());
            codeGroup.setProject(project.get());
            codeGroup.setAppClient(codeGroupPutModel.getAppClient());
            codeGroupRepository.saveAndFlush(codeGroup);
            codeGroup.setVersionIdsingle(codeGroupPutModel.getVersionIdAll());
            createProjectForCodeGroup(codeGroup, codeGroupPutModel);
            String uuidToken = UUID.randomUUID().toString();
            if (StringUtils.isNotBlank(codeGroupPutModel.getGitpassword()) && vaultHelper.savePassword(codeGroupPutModel.getGitpassword(), uuidToken)) {
                codeGroup.setRepoPassword(uuidToken);
            } else {
                codeGroup.setRepoPassword(codeGroupPutModel.getGitpassword());
            }
            codeGroupRepository.saveAndFlush(codeGroup);
            log.info("{} - Created new CodeGroup [{}] {}", principal.getName(), project.get().getName(), codeGroup.getName());
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    /**
     * Removing auth info from model
     * @param codeGroupPutModel
     * @return
     */
    private String setRepoUrl(CodeGroupPutModel codeGroupPutModel) {
        Pattern pattern = Pattern.compile("https?:\\/\\/(.*:.*@).*");
        Matcher matcher = pattern.matcher(codeGroupPutModel.getGiturl());
        if (matcher.find())
            return codeGroupPutModel.getGiturl().replace(matcher.group(1), "");
        else
           return codeGroupPutModel.getGiturl();
    }

    private void createProjectForCodeGroup(CodeGroup codeGroup, CodeGroupPutModel codeGroupPutModel) {
        CodeProject cp = new CodeProject();
        cp.setName(codeGroup.getName());
        cp.setCodeGroup(codeGroup);
        cp.setBranch(codeGroupPutModel.getBranch()!=null ?  codeGroupPutModel.getBranch() : Constants.CODE_DEFAULT_BRANCH);
        cp.setRepoUrl(codeGroup.getRepoUrl());
        cp.setRepoPassword(codeGroup.getRepoPassword());
        cp.setRepoUsername(codeGroup.getRepoUsername());
        cp.setTechnique(codeGroup.getTechnique());
        cp.setInQueue(false);
        cp.setdTrackUuid(codeGroupPutModel.getdTrackUuid());
        cp = codeProjectRepository.saveAndFlush(cp);
        cxBranchRepository.save(new CxBranch(cp, codeGroupPutModel.getBranch()));
    }

    public ResponseEntity<Status> saveCodeProject(Long id, CodeProjectPutModel codeProjectPutModel, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        Optional<CodeGroup> codeGroup = codeGroupRepository.findById(codeProjectPutModel.getCodeGroup());
        if (project.isPresent() &&
                permissionFactory.canUserAccessProject(principal,project.get()) &&
                codeGroup.isPresent() &&
                codeGroup.get().getProject().getId().equals(project.get().getId())){
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
            log.info("{} - Created new CodeProject [{} / {} ] {}", principal.getName(), project.get().getName(), codeGroup.get().getName(), codeProject.getName());
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> runSelectedCodeProjects(Long id, List<RunScanForCodeProject> runScanForCodeProjects, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return codeScanService.codescanrunSelectedCodeProjectsScan(id, runScanForCodeProjects, principal);
    }

    public ResponseEntity<Status> enableAutoScanForCodeProjects(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            for (CodeGroup codeGroup : project.get().getCodes()){
                codeGroup.setAuto(true);
                codeGroupRepository.save(codeGroup);
            }
            project.get().setAutoCodeScan(true);
            projectRepository.save(project.get());
            log.info("{} - Enabled auto SAST scan for {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> runSingleCodeProjectScan(Long codeProjectId, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        boolean putToQueue = codeScanService.putCodeProjectToQueue(codeProjectId, principal);
        if (putToQueue){
            log.info("{} - Run SAST scan for {} - scope single", LogUtil.prepare(principal.getName()), LogUtil.prepare(codeProjectId.toString()));
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        } }

    @Transactional
    public ResponseEntity<Status> deleteCodeProject(Long codeProjectId, Principal principal) {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(codeProjectId);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getCodeGroup().getProject())){
            codeProjectRepository.removeCodeGroup(codeProject.get().getId());
            log.info("{} - Deleted codeproject [{}] {}", principal.getName(), codeProject.get().getCodeGroup().getProject().getName(), codeProject.get().getName());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }
    @Transactional
    public ResponseEntity<List<ProjectVulnerability>> showCodeVulns(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
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
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            for (CodeGroup codeGroup : project.get().getCodes()){
                codeGroup.setAuto(false);
                codeGroupRepository.save(codeGroup);
            }
            project.get().setAutoCodeScan(false);
            projectRepository.save(project.get());
            log.info("{} - Disabled auto SAST scan for {}", principal.getName(), project.get().getName());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> editCodeProject(Long id, EditCodeProjectModel editCodeProjectModel, Principal principal) {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(id);
        try{
            if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getCodeGroup().getProject())){
                if (StringUtils.isNotBlank(editCodeProjectModel.getdTrackUuid()) && !codeProject.get().getdTrackUuid().equals(editCodeProjectModel.getdTrackUuid())) {
                    UUID uuid = UUID.fromString(editCodeProjectModel.getdTrackUuid());
                    codeProject.get().setdTrackUuid(editCodeProjectModel.getdTrackUuid());
                    codeProjectRepository.save(codeProject.get());
                    log.info("{} Edited CodeProject {} scope DtrackUUID", principal.getName(), codeProject.get().getName());
                }
                if (editCodeProjectModel.getSastProject() > 0 && codeProject.get().getCodeGroup().getVersionIdAll() != editCodeProjectModel.getSastProject() ) {
                    codeProject.get().getCodeGroup().setVersionIdAll(editCodeProjectModel.getSastProject());
                    if (!codeProject.get().getCodeGroup().getHasProjects()){
                        codeProject.get().getCodeGroup().setVersionIdsingle(editCodeProjectModel.getSastProject());
                        codeProject.get().getCodeGroup().setVersionIdAll(editCodeProjectModel.getSastProject());
                    }
                    codeGroupRepository.save(codeProject.get().getCodeGroup());
                    log.info("{} Edited CodeProject {} scope SAST scanner integration", principal.getName(), codeProject.get().getName());
                }
                if (StringUtils.isNotBlank(editCodeProjectModel.getBranch()) && !codeProject.get().getBranch().equals(editCodeProjectModel.getBranch())){
                    codeProject.get().setBranch(editCodeProjectModel.getBranch());
                    log.info("{} Edited CodeProject {} scope Branch, new value: {}", principal.getName(), codeProject.get().getName(), LogUtil.prepare(editCodeProjectModel.getBranch()));
                }
                if (StringUtils.isNotBlank(editCodeProjectModel.getRepoUrl()) && !codeProject.get().getRepoUrl().equals(editCodeProjectModel.getRepoUrl())){
                    codeProject.get().setRepoUrl(editCodeProjectModel.getRepoUrl());
                    log.info("{} Edited CodeProject {} scope RepoURL, new value: {}", principal.getName(), codeProject.get().getName(), LogUtil.prepare(editCodeProjectModel.getRepoUrl()));

                }
                if (StringUtils.isNotBlank(editCodeProjectModel.getRepoUsername()) && !codeProject.get().getRepoUsername().equals(editCodeProjectModel.getRepoUsername())){
                    codeProject.get().setRepoUsername(editCodeProjectModel.getRepoUsername());
                    log.info("{} Edited CodeProject {} scope RepoUsername, new value: {}", principal.getName(), codeProject.get().getName(), LogUtil.prepare(editCodeProjectModel.getRepoUsername()));

                }
                if (!editCodeProjectModel.getRepoPassword().equals(Constants.DUMMY_PASSWORD) && !editCodeProjectModel.getRepoPassword().equals(Constants.DUMMY_PASSWORD2)){
                    String uuidToken = UUID.randomUUID().toString();
                    if (vaultHelper.savePassword(editCodeProjectModel.getRepoPassword(), uuidToken)) {
                        codeProject.get().setRepoPassword(uuidToken);
                    } else {
                        codeProject.get().setRepoPassword(editCodeProjectModel.getRepoPassword());
                    }
                    log.info("{} Edited CodeProject {} scope Password", principal.getName(), codeProject.get().getName());
                }
                codeProjectRepository.save(codeProject.get());
                return new ResponseEntity<>(HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } catch (IllegalArgumentException | NullPointerException exception){
            log.warn("{} failed to edit codeProject {} due to wrong UUID format", principal.getName(), id);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity<Status> createDTrackProject(Long id, Principal principal) {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(id);
        try{
            if (codeProject.isPresent() &&
                    permissionFactory.canUserAccessProject(principal, codeProject.get().getCodeGroup().getProject()) &&
                    openSourceScanService.createProjectOnOpenSourceScanner(codeProject.get()) ) {

                log.info("{} Successfully Created dTrack Project {}", principal.getName(), codeProject.get().getName());
                return new ResponseEntity<>(HttpStatus.OK);

            }
        } catch (IllegalArgumentException |IOException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException | KeyManagementException exception){
            log.warn("{} failed to create dTrackProject {} due to wrong UUID format", principal.getName(), id);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity<List<Projects>> getdTracksProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return new ResponseEntity<>(openSourceScanService.getOpenSourceProjectFromScanner(), HttpStatus.OK);
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
}
