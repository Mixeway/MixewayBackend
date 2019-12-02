package io.mixeway.rest.project.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.plugins.codescan.service.CodeScanClient;
import io.mixeway.rest.project.model.*;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeVuln;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.db.repository.CodeVulnRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.pojo.Status;

import javax.transaction.Transactional;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

@Service
public class CodeService {
    private static final Logger log = LoggerFactory.getLogger(CodeService.class);
    private final ProjectRepository projectRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final CodeGroupRepository codeGroupRepository;
    private final VaultOperations operations;
    private final List<CodeScanClient> codeScanClients;
    private final CodeVulnRepository codeVulnRepository;

    @Autowired
    CodeService(ProjectRepository projectRepository, CodeProjectRepository codeProjectRepository,
                ProjectRiskAnalyzer projectRiskAnalyzer, CodeGroupRepository codeGroupRepository,
                VaultOperations operations, List<CodeScanClient> codeScanClients,
                CodeVulnRepository codeVulnRepository) {
        this.projectRepository = projectRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.projectRiskAnalyzer = projectRiskAnalyzer;
        this.operations = operations;
        this.codeGroupRepository = codeGroupRepository;
        this.codeVulnRepository = codeVulnRepository;
        this.codeScanClients = codeScanClients;
    }

    public ResponseEntity<CodeCard> showCodeRepos(Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if ( project.isPresent()){
            CodeCard codeCard = new CodeCard();
            codeCard.setCodeAutoScan(project.get().isAutoCodeScan());
            List<CodeModel> codeModels = new ArrayList<>();
            for (CodeProject cp : codeProjectRepository.findByCodeGroupIn(project.get().getCodes())){
                CodeModel codeModel = new CodeModel();
                codeModel.setCodeProject(cp.getName());
                codeModel.setCodeGroup(cp.getCodeGroup().getName());
                codeModel.setId(cp.getId());
                codeModel.setRunning(cp.getCodeGroup().isRunning());
                int risk = projectRiskAnalyzer.getCodeProjectRisk(cp);
                codeModel.setRisk(Math.min(risk, 100));
                codeModels.add(codeModel);
            }
            codeCard.setCodeModels(codeModels);
            return new ResponseEntity<>(codeCard, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }
    public ResponseEntity<List<CodeGroup>> showCodeGroups(Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
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
            codeGroup.setRepoPassword(UUID.randomUUID().toString());
            codeGroup.setTechnique(codeGroupPutModel.getTech());
            codeGroup.setHasProjects(codeGroupPutModel.isChilds());
            codeGroup.setAuto(codeGroupPutModel.isAutoScan());
            codeGroup.setVersionIdAll(codeGroupPutModel.getVersionIdAll());
            codeGroup.setVersionIdsingle(codeGroupPutModel.getVersionIdSingle());
            codeGroup.setProject(project.get());
            codeGroupRepository.save(codeGroup);
            Map<String, String> mapa = new HashMap<>();
            mapa.put("password", codeGroupPutModel.getGitpassword());
            operations.write("secret/"+codeGroup.getRepoPassword(), mapa);
            log.info("{} - Created new CodeGroup [{}] {}", username, project.get().getName(), codeGroup.getName());
            return new ResponseEntity<>(null,HttpStatus.CREATED);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> saveCodeProject(Long id, CodeProjectPutModel codeProjectPutModel, String username) {
        Optional<Project> project = projectRepository.findById(id);
        Optional<CodeGroup> codeGroup = codeGroupRepository.findById(codeProjectPutModel.getCodeGroup());
        if (project.isPresent() && codeGroup.isPresent() && codeGroup.get().getProject() == project.get()){
            CodeProject codeProject = new CodeProject();
            codeProject.setCodeGroup(codeGroup.get());
            codeProject.setName(codeProjectPutModel.getCodeProjectName());
            codeProject.setSkipAllScan(false);
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
        try {
            Optional<Project> project = projectRepository.findById(id);
            if (project.isPresent()) {
                for (RunScanForCodeProject runScun : runScanForCodeProjects) {
                    Optional<CodeProject> codeProject = codeProjectRepository.findById(runScun.getId());
                    if (codeProject.isPresent() && codeProject.get().getCodeGroup().getProject() == project.get()) {
                        for(CodeScanClient codeScanClient : codeScanClients){
                            if (codeScanClient.canProcessRequest(codeProject.get().getCodeGroup())){
                                codeScanClient.runScan(codeProject.get().getCodeGroup(), codeProject.get());
                            }
                        }
                    }
                }
                log.info("{} - Run SAST scan for {} - scope partial", username, project.get().getName());
                return new ResponseEntity<>(null, HttpStatus.OK);
            } else {
                return new ResponseEntity<>(null, HttpStatus.EXPECTATION_FAILED);
            }
        } catch (IndexOutOfBoundsException ioob){
            return new ResponseEntity<>(null, HttpStatus.EXPECTATION_FAILED);
        }
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
        try {
            Optional<CodeProject> codeProject = codeProjectRepository.findById(codeProjectId);
            if (codeProject.isPresent() ) {
                for(CodeScanClient codeScanClient : codeScanClients){
                    if (codeScanClient.canProcessRequest(codeProject.get().getCodeGroup())){
                        codeScanClient.runScan(codeProject.get().getCodeGroup(), codeProject.get());
                    }
                }
            }
            log.info("{} - Run SAST scan for {} - scope single", username, codeProject.get().getCodeGroup().getProject().getName());
            return new ResponseEntity<>(null, HttpStatus.OK);
        } catch (IndexOutOfBoundsException e) {
            return new ResponseEntity<>(null, HttpStatus.EXPECTATION_FAILED);
        }
    }

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
    public ResponseEntity<List<CodeVuln>> showCodeVulns(Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            List<CodeVuln> codeVulns = codeVulnRepository.findByCodeGroupIn(project.get().getCodes());
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
}