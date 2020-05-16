package io.mixeway.integrations.codescan.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.integrations.opensourcescan.plugins.mvndependencycheck.model.SASTRequestVerify;
import io.mixeway.integrations.codescan.model.CodeScanRequestModel;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.project.model.RunScanForCodeProject;
import io.mixeway.rest.project.model.SASTProject;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.integrations.utils.CodeAccessVerifier;
import io.mixeway.pojo.Status;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;

/**
 * @author gsiewruk
 */
@Service
public class CodeScanService {
    private static final Logger log = LoggerFactory.getLogger(CodeScanService.class);
    private final ProjectRepository projectRepository;
    private final CodeGroupRepository codeGroupRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final CodeVulnRepository codeVulnRepository;
    private final CodeAccessVerifier codeAccessVerifier;
    private final VaultHelper vaultHelper;
    private final List<CodeScanClient> codeScanClients;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final CiOperationsRepository ciOperationsRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;


    CodeScanService(ProjectRepository projectRepository, CodeGroupRepository codeGroupRepository, CodeProjectRepository codeProjectRepository,
                    CodeVulnRepository codeVulnRepository, CodeAccessVerifier codeAccessVerifier, VaultHelper vaultHelper,
                    List<CodeScanClient> codeScanClients, ScannerRepository scannerRepository, ScannerTypeRepository scannerTypeRepository,
                    CiOperationsRepository ciOperationsRepository, ProjectRiskAnalyzer projectRiskAnalyzer){
        this.projectRepository = projectRepository;
        this.codeGroupRepository = codeGroupRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.codeVulnRepository = codeVulnRepository;
        this.codeAccessVerifier = codeAccessVerifier;
        this.vaultHelper = vaultHelper;
        this.codeScanClients = codeScanClients;
        this.ciOperationsRepository = ciOperationsRepository;
        this.scannerRepository = scannerRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.projectRiskAnalyzer = projectRiskAnalyzer;
    }

    //PREPARE SCAN

    /**
     * Method for getting CodeVulns for given names
     *
     * @param projectId id of a Project entity
     * @param groupName name of CodeGroup entity
     * @param projectName name of CodeProject entity
     * @return List of a CodeVulns for a given CodeProject
     */
    public ResponseEntity<List<CodeVuln>> getResultsForProject(long projectId, String groupName, String projectName){
        Optional<Project> project = projectRepository.findById(projectId);
        if (codeAccessVerifier.verifyPermissions(projectId,groupName,projectName,false).getValid() && project.isPresent()){
            CodeProject cp = codeProjectRepository.findByCodeGroupAndName(codeGroupRepository
                    .findByProjectAndName(project.get(),groupName).orElse(null),projectName).orElse(null);
            List<CodeVuln> codeVulns = codeVulnRepository.findByCodeProjectAndAnalysisNot(cp,"Not an Issue");
            new ResponseEntity<>(codeVulns, HttpStatus.OK);

        } else
            new ResponseEntity<List<CodeVuln>>(new ArrayList<>(), HttpStatus.PRECONDITION_FAILED);


        return null;
    }

    /**
     * Method to return CodeVulns for given CodeGroup. It contains CodeVulns for each CodeProject
     * which is related with given CodeGroup
     *
     * @param projectId id of a Project entity
     * @param groupName name of CodeGroup entity
     * @return List of CodeVulns for given CodeGroup
     */
    public ResponseEntity<List<CodeVuln>> getResultsForGroup(long projectId, String groupName){

        if (codeAccessVerifier.verifyPermissions(projectId,groupName,null, false).getValid()){
            CodeGroup cg = codeGroupRepository
                    .findByProjectAndName(projectRepository.findById(projectId).orElse(null),groupName).orElse(null);
            List<CodeVuln> codeVulns = codeVulnRepository.findByCodeGroupAndAnalysisNot(cg,"Not an Issue");
            new ResponseEntity<>(codeVulns, HttpStatus.OK);

        } else
            new ResponseEntity<List<CodeVuln>>(new ArrayList<>(), HttpStatus.PRECONDITION_FAILED);


        return null;
    }

    /**
     * Method which puts given CodeProject into scan queue.
     * If there are present objects if CodeProject and CodeGroup they are updated. When CodeScanRequest contains
     * informations about new objects they are created.
     *
     * @param codeScanRequest object passed from REST API
     * @return Status entity with proper HTTPStatus. CREATED when everytihng is ok and BAD_REQUEST if it is not
     */
    public ResponseEntity<Status> performScanFromScanManager(CodeScanRequestModel codeScanRequest) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        if (codeScanRequest.getCiid() != null && !codeScanRequest.getCiid().equals("")){
            Optional<List<Project>> projects = projectRepository.findByCiid(codeScanRequest.getCiid());
            Project project;
            if (projects.isPresent()){
                project = projects.get().stream().findFirst().orElse(null);
            } else {
                project = new Project();
                project.setName(codeScanRequest.getProjectName());
                project.setCiid(codeScanRequest.getCiid());
                project.setEnableVulnManage(codeScanRequest.getEnableVulnManage().isPresent() ? codeScanRequest.getEnableVulnManage().get() : true);
                project = projectRepository.save(project);
            }

            String requestId = verifyAndCreateOrUpdateCodeProjectInformations(codeScanRequest,project);
            return new ResponseEntity<>(new Status("Scan requested",requestId), HttpStatus.CREATED);

        } else {
            return new ResponseEntity<>(new Status("Missing information about project."), HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Execute informations sent in CodeScanRequests. There result is to put CodeProject from requenst into scan queue by settin inQueue to true
     * There are three options:
     * 1. Both CodeProject and CodeGroup is new - create both and put CodeProject to queue
     * 2. CodeGroup exist and CodeProject is new - create CodeProject and put it to queue
     * 3. CodeGroup and CodeProject exists - put CodeProject to Queue
     *
     * @param codeScanRequest proper object of CodeScanRequest
     * @param project Project on which behalf request is being executed
     * @return requestId of created scan
     */
    private String verifyAndCreateOrUpdateCodeProjectInformations(CodeScanRequestModel codeScanRequest, Project project) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        String requestId;
        Optional<CodeGroup> codeGroup = codeGroupRepository.findByProjectAndName(project,codeScanRequest.getCodeGroupName());
        if (codeGroup.isPresent()){
            Optional<CodeProject> codeProject = codeProjectRepository.findByCodeGroupAndName(codeGroup.get(),codeScanRequest.getCodeProjectName());
            if (codeProject.isPresent()){
                CodeGroup updatedCodeGroup = updateCodeGroup(codeScanRequest,codeGroup.get());
                CodeProject updatedCodeProject = updateCodeProject(codeScanRequest,project,codeProject.get());
                updatedCodeProject.setInQueue(true);
                codeProjectRepository.save(updatedCodeProject);
                requestId = Objects.requireNonNull(codeProjectRepository.findById(updatedCodeProject.getId()).orElse(null)).getRequestId();
            } else {
                CodeGroup updatedCodeGroup = updateCodeGroup(codeScanRequest,codeGroup.get());
                CodeProject newCodeProject = createNewCodeProject(codeScanRequest,project,updatedCodeGroup);
                newCodeProject.setInQueue(true);
                codeProjectRepository.save(newCodeProject);
                requestId = Objects.requireNonNull(codeProjectRepository.findById(newCodeProject.getId()).orElse(null)).getRequestId();
            }
        } else {
            CodeGroup newCodeGroup = createNewCodeGroup(codeScanRequest,project);
            CodeProject newCodeProject = createNewCodeProject(codeScanRequest,project,newCodeGroup);
            newCodeProject.setInQueue(true);
            codeProjectRepository.save(newCodeProject);
            requestId = Objects.requireNonNull(codeProjectRepository.findById(newCodeProject.getId()).orElse(null)).getRequestId();
        }
        return requestId;
    }

    /**
     * Creates new CodeProjcet base on configuration from CodeScanRequest
     *
     * @param codeScanRequest CodeScanRequest from REST API
     * @param project Project on which behalf request is being executed
     * @param newCodeGroup CodeGroup to be linked with
     * @return created CodeProject
     */
    private CodeProject createNewCodeProject(CodeScanRequestModel codeScanRequest, Project project, CodeGroup newCodeGroup) {
        CodeProject codeProject = new CodeProject();
        codeProject.setName(codeScanRequest.getCodeProjectName());
        codeProject.setCodeGroup(newCodeGroup);
        codeProject.setTechnique(codeScanRequest.getTech());
        codeProject.setBranch(codeScanRequest.getBranch());
        codeProject.setRepoUrl(codeScanRequest.getRepoUrl());
        codeProject = codeProjectRepository.save(codeProject);
        log.info("{} - Created new CodeProject [{}] {}", "ScanManager", project.getName(), codeProject.getName());
        return codeProject;
    }
    /**
     * Updates CodeProjcet base on configuration from CodeScanRequest
     * Fields to update:
     * 1. Branch
     * 2. Repo URL
     * 3. Technique
     *
     * @param codeScanRequest CodeScanRequest from REST API
     * @param project Project on which behalf request is being executed
     * @param codeProject CodeProject to update
     * @return created CodeProject
     */
    private CodeProject updateCodeProject(CodeScanRequestModel codeScanRequest, Project project, CodeProject codeProject) {
        codeProject.setTechnique(codeScanRequest.getTech());
        codeProject.setBranch(codeScanRequest.getBranch());
        codeProject.setRepoUrl(codeScanRequest.getRepoUrl());
        codeProject = codeProjectRepository.save(codeProject);
        log.info("{} - Updated CodeProject [{}] {}", "ScanManager", project.getName(), codeProject.getName());
        return codeProject;
    }

    /**
     * Creates new CodeGroup base on configuration from CodeScanRequest
     *
     * @param codeScanRequest CodeScanRequest from REST API
     * @param project Project on which behalf request is being done
     * @return created CodeGroup
     */
    private CodeGroup createNewCodeGroup(CodeScanRequestModel codeScanRequest, Project project){
        CodeGroup newCodeGroup = new CodeGroup();
        newCodeGroup.setProject(project);
        newCodeGroup.setName(codeScanRequest.getCodeGroupName());
        newCodeGroup.setHasProjects(false);
        newCodeGroup.setAuto(false);
        newCodeGroup = updateCodeGroup(codeScanRequest, newCodeGroup);
        log.info("{} - Created new CodeGroup [{}] {}", "ScanManager", project.getName(), newCodeGroup.getName());
        return newCodeGroup;
    }

    /**
     * Method which update CodeGroup with values from CodeScanRequest
     * Update fields:
     * 1. Technique
     * 2. RepoURL
     * 3. versionIdAll
     *
     * @param codeScanRequest CodeScanRequest from REST API
     * @param codeGroup updated CodeGroup
     * @return
     */
    @NotNull
    private CodeGroup updateCodeGroup(CodeScanRequestModel codeScanRequest, CodeGroup codeGroup) {
        codeGroup.setTechnique(codeScanRequest.getTech());
        codeGroup.setRepoUrl(codeScanRequest.getRepoUrl());
        codeGroup.setVersionIdAll(codeScanRequest.getFortifySSCVersionId());
        codeGroup = codeGroupRepository.save(codeGroup);
        String uuidToken = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(codeScanRequest.getRepoPassword(), uuidToken)){
            codeGroup.setRepoPassword(uuidToken);
        } else {
            codeGroup.setRepoPassword(codeScanRequest.getRepoPassword());
        }
        return codeGroup;
    }

    /**
     * Method executed by scheduler to load Vulnerabilities Reports for each entity within database
     */
    public void schedulerReportSynchro() throws CertificateException, ParseException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, UnrecoverableKeyException, IOException {
        List<CodeGroup> groups = codeGroupRepository.findAll();
        log.info("SAST Offline synchronization Started");
        Optional<Scanner> sastScanner = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true).stream().findFirst();
        if (sastScanner.isPresent() && sastScanner.get().getStatus()) {
            for (CodeGroup group : groups) {
                List<CodeVuln> tmpVulns = deleteVulnsForCodeGroup(group);
                if (group.getVersionIdAll() > 0) {
                    for(CodeScanClient codeScanClient : codeScanClients){
                        if (codeScanClient.canProcessRequest(sastScanner.get())){
                            log.info("Starting loading SAST vulns for - {}", group.getName());
                            codeScanClient.loadVulnerabilities(sastScanner.get(),group,null,false,null,tmpVulns);
                            log.info("Loaded SAST vulns for - {}", group.getName());
                        }
                    }
                }

            }
        }
        log.info("SAST Offline synchronization completed");
    }

    /**
     * Method which put each codegroup in scan queue by Project.autoCodeScan = true
     */
    public void schedulerRunAutoScans() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        log.info("Starting Fortify Scheduled Scans");
        //List<CodeGroup> groups = codeGroupRepository.findByAuto(true);
        List<Project> projects = projectRepository.findByAutoCodeScan(true);
        Optional<Scanner> sastScanner = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true).stream().findFirst();
        if ( sastScanner.isPresent() &&  sastScanner.get().getStatus()) {
            for (Project p : projects){
                for (CodeGroup cg : p.getCodes()){
                    for(CodeScanClient codeScanClient : codeScanClients){
                        if (codeScanClient.canProcessRequest(sastScanner.get())){
                            codeScanClient.runScan(cg,null);
                        }
                    }
                }
            }
        }
    }

    /**
     * Method which is looking for CodeProject and CodeGroup with running = true
     * Verify if scan is done, and if so loads vulnerabilities
     */
    public void getResultsForRunningScan() throws CertificateException, ParseException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, UnrecoverableKeyException, IOException {
        Optional<Scanner> sastScanner = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true).stream().findFirst();
        if (sastScanner.isPresent()) {
            for (CodeProject codeProject : codeProjectRepository.findByRunning(true)) {
                List<CodeVuln> codeVulns = codeVulns = deleteVulnsForProject(codeProject);
                for (CodeScanClient codeScanClient : codeScanClients) {
                    if (codeScanClient.canProcessRequest(sastScanner.get()) && codeScanClient.isScanDone(null, codeProject)) {
                        codeScanClient.loadVulnerabilities(sastScanner.get(), codeProject.getCodeGroup(), null, true, codeProject, codeVulns);
                        log.info("Vulerabilities for codescan for {} with scope of {} loaded - single app", codeProject.getCodeGroup().getName(), codeProject.getName());
                        if (StringUtils.isNotBlank(codeProject.getCommitid()))
                            updateCiOperationsForDoneSastScan(codeProject);
                        codeProject.setRunning(false);
                        codeProject.getCodeGroup().setRunning(false);
                        codeProject.getCodeGroup().setRequestid(null);
                        codeProject.getCodeGroup().setScanid(null);
                        codeProject.getCodeGroup().setScope(null);
                        codeProject.setRisk(projectRiskAnalyzer.getCodeProjectRisk(codeProject) + projectRiskAnalyzer.getCodeProjectOpenSourceRisk(codeProject));
                        codeGroupRepository.save(codeProject.getCodeGroup());
                        codeProjectRepository.save(codeProject);
                    }
                }

            }
            List<CodeGroup> codeGroups = codeGroupRepository.findByRunning(true);
            for (CodeGroup codeGroup : codeGroups) {
                for (CodeScanClient codeScanClient : codeScanClients) {
                    if (codeScanClient.canProcessRequest(sastScanner.get()) && codeScanClient.isScanDone(codeGroup,null) ) {
                        deleteVulnsForCodeGroup(codeGroup);
                        codeScanClient.loadVulnerabilities(sastScanner.get(), codeGroup, null, false, null, null);
                        codeGroup.setRunning(false);
                        codeGroup.setRequestid(null);
                        codeGroup.setScanid(null);
                        codeGroup.setScope(null);
                        codeGroupRepository.save(codeGroup);
                    }
                }
            }
        }
    }

    /**
     * Method which updates CI Operation and end it if code scan is done
     * @param codeProject CodeProject for CI Operation to be linked with
     */
    private void updateCiOperationsForDoneSastScan(CodeProject codeProject) {
        Optional<CiOperations> operations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,codeProject.getCommitid());
        if (operations.isPresent()){
            CiOperations operation = operations.get();
            operation.setSastScan(true);
            int sastCrit = codeVulnRepository.findByCodeProjectAndSeverityAndAnalysis(codeProject, Constants.VULN_CRITICALITY_CRITICAL, Constants.FORTIFY_ANALYSIS_EXPLOITABLE).size();
            int sastHigh = codeVulnRepository.findByCodeProjectAndSeverityAndAnalysis(codeProject, Constants.VULN_CRITICALITY_HIGH, Constants.FORTIFY_ANALYSIS_EXPLOITABLE).size();
            operation.setSastCrit(sastCrit);
            operation.setSastHigh(sastHigh);
            operation.setEnded(new Date());
            operation.setResult((sastCrit + sastHigh) > 5 ? "Not Ok" : "Ok");
            ciOperationsRepository.save(operation);
            log.info("CI Operation updated for {} - {} settings SAST scan to true", codeProject.getCodeGroup().getProject().getName(),codeProject.getName());
        }
    }

    /**
     * Get the CodeProjects and CodeGroups with inQueue=true
     * Verify if scan can be run and then runs it.
     */
    public void runFromQueue() {
        Optional<Scanner> fortify = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true).stream().findFirst();
        if (fortify.isPresent() && fortify.get().getStatus()) {
            try {
                for (CodeProject cp : codeProjectRepository.findByInQueue(true)) {
                    if (canScanCodeProject(cp)) {
                        for (CodeScanClient codeScanClient : codeScanClients) {
                            if (codeScanClient.canProcessRequest(cp.getCodeGroup())) {
                                log.info("Ready to scan [scope {}] {}, taking it from the queue", cp.getName(), cp.getCodeGroup().getName());
                                cp.setInQueue(false);
                                codeProjectRepository.saveAndFlush(cp);
                                codeScanClient.runScan(cp.getCodeGroup(), cp);
                            }
                        }
                    }
                }
                for (CodeGroup cg : codeGroupRepository.findByInQueue(true)) {
                    if (codeGroupRepository.countByRunning(true) == 0) {
                        for (CodeScanClient codeScanClient : codeScanClients) {
                            if (codeScanClient.canProcessRequest(cg)) {
                                log.info("Ready to scan [scope ALL] {}, taking it from the queue", cg.getName());
                                cg.setInQueue(false);
                                codeGroupRepository.saveAndFlush(cg);
                                codeScanClient.runScan(cg, null);
                            }
                        }
                    }
                }

            } catch (IndexOutOfBoundsException ex) {
                log.debug("Fortify configuration missing");
            } catch (HttpClientErrorException ex) {
                log.warn("HttpClientErrorException with code [{}] during cloud scan job synchro ", ex.getStatusCode().toString());
            } catch (ParseException | JSONException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException e) {
                log.warn("Exception came up during running scan {}", e.getLocalizedMessage());
            }
        }
    }


    /**
     * Method which verify if CodeProject scan can be started
     * @param cp CodeProject to be verified
     * @return true if scan can be run, false if not
     */
    private boolean canScanCodeProject(CodeProject cp) {
        if (cp.getRunning())
            return false;
        else if (cp.getCodeGroup().getProjects().stream().anyMatch(CodeProject::getRunning))
            return false;
        else if (cp.getCodeGroup().isRunning())
            return false;
        else return true;
    }


    /**
     * Deletes old vulnerabilities for CodeGroup
     *
     * @param group codeGroup to delate vulns for
     * @return List of deleted vulns to set proper status
     */
    private List<CodeVuln> deleteVulnsForCodeGroup(CodeGroup group) {
        List<CodeVuln> tmpVulns = new ArrayList<>();
        if (group.getHasProjects()) {
            for (CodeProject cp : group.getProjects()) {
                tmpVulns.addAll(codeVulnRepository.findByCodeProject(cp));
                codeVulnRepository.deleteVulnsForCodeProject(cp);
            }
        } else{
            tmpVulns.addAll(codeVulnRepository.findByCodeGroup(group));
            codeVulnRepository.deleteVulnsForCodeGroup(group);
        }
        return tmpVulns;
    }
    /**
     * Deletes old vulnerabilities for CodeProject
     *
     * @param codeProject CodeProject to delate vulns for
     * @return List of deleted vulns to set proper status
     */
    private List<CodeVuln> deleteVulnsForProject(CodeProject codeProject){
        List<CodeVuln> codeVulns = codeVulnRepository.findByCodeProject(codeProject);
        codeVulnRepository.deleteVulnsForCodeProject(codeProject);
        return codeVulns;
    }

    /**
     * Method which run scan for given parameters
     *
     * @param id of project from REST API
     * @param groupName of CodeGroup from REST API
     * @param projectName of CodeProject from REST API
     * @return ResponseEntity with HttpStatus.CREATED when scan is properly scheduled, HttpStatus.PRECONDITION_FAILED if it can be not queued.
     */
    @Deprecated
    public ResponseEntity<Status> createScanForCodeProject(Long id, String groupName, String projectName) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyPermissions(id,groupName,projectName,false);
        if (sastRequestVerify.getValid()){
            for(CodeScanClient codeScanClient : codeScanClients){
                if (codeScanClient.canProcessRequest(sastRequestVerify.getCg())){
                    if (codeScanClient.runScan(sastRequestVerify.getCg(),sastRequestVerify.getCp())){
                        return new ResponseEntity<>(new Status("OK"), HttpStatus.CREATED);
                    } else {
                        return new ResponseEntity<>(new Status("Queued"), HttpStatus.CREATED);
                    }
                }
            }
        } else {
            return new ResponseEntity<>(new Status("Scan for given resource is not yet configured."), HttpStatus.PRECONDITION_FAILED);
        }
        return new ResponseEntity<>(new Status("Something went wrong"), HttpStatus.PRECONDITION_FAILED);
    }

    /**
     * Used for CI Jobs integrated with Fortify SCA. Gets jobId of manualy executed CloudScan and link it with codeproject in order
     * to get properly vulnerabilities detected by Fortify SSC and CloudScan
     *
     * @param id of project from REST API
     * @param groupName of CodeGroup from REST API
     * @param projectName of CodeProject from REST API
     * @param jobId of CloudScan job
     * @return ResponseEntity with HttpStatus.OK when jobId is properly set, HttpStatus.PRECONDITION_FAILED if not.
     */
    public ResponseEntity<Status> putInformationAboutJob(Long id, String groupName, String projectName, String jobId) {
        SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyPermissions(id,groupName,projectName,false);
        if (sastRequestVerify.getValid()){
            for(CodeScanClient codeScanClient : codeScanClients){
                if (codeScanClient.canProcessRequest(sastRequestVerify.getCg())){
                    codeScanClient.putInformationAboutScanFromRemote(sastRequestVerify.getCp(), sastRequestVerify.getCg(), jobId);
                    return new ResponseEntity<>(new Status("OK"), HttpStatus.OK);
                }
            }
        } else {
            return new ResponseEntity<>(new Status("Scan for given resource is not yet configured."), HttpStatus.PRECONDITION_FAILED);
        }
        return new ResponseEntity<>(new Status("Something went wrong"), HttpStatus.PRECONDITION_FAILED);
    }

    /**
     * Method which take List of RunScanForCodeProject objects and then it run scan for every scan from list
     *
     * @param id of Project
     * @param runScanForCodeProjects list of projects where whihch scan should be started
     * @param username principal who is executing the request
     * @return ResponseEntity with HttpStatus.OK if scan is properly executed HttpStatus.PREDONDITION_FAILED if there is a problem
     */
    public ResponseEntity<Status> codescanrunSelectedCodeProjectsScan(Long id, List<RunScanForCodeProject> runScanForCodeProjects, String username) {
        try {
            Optional<Project> project = projectRepository.findById(id);
            if (project.isPresent()) {
                for (RunScanForCodeProject runScun : runScanForCodeProjects) {
                    Optional<CodeProject> codeProject = codeProjectRepository.findById(runScun.getId());
                    if (codeProject.isPresent() && codeProject.get().getCodeGroup().getProject() == project.get()) {
                        for(CodeScanClient codeScanClient : codeScanClients){
                            if (codeScanClient.canProcessRequest(codeProject.get().getCodeGroup())){
                                codeScanClient.runScan(codeProject.get().getCodeGroup(), codeProject.get());
                                break;
                            }
                        }
                    }
                }
                log.info("{} - Run SAST scan for {} - scope partial", LogUtil.prepare(username), LogUtil.prepare(project.get().getName()));

                return new ResponseEntity<>(null, HttpStatus.OK);
            }
        } catch (IndexOutOfBoundsException | ParseException | JSONException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException ioob){
            log.error("Problem with scanning selected projects reason is {}", ioob.getLocalizedMessage());
        }
        return new ResponseEntity<>(null, HttpStatus.EXPECTATION_FAILED);
    }

    /**
     * Method of putting CodeProject into scan queue by codeproject.id
     *
     * @param id of CodeProject entity
     * @return true if scan is properly put into queue and false if there is no such CodeProject
     */
    public boolean putCodeProjectToQueue(Long id){
        Optional<CodeProject> codeProject = codeProjectRepository.findById(id);
        if (codeProject.isPresent()){
            codeProject.get().setInQueue(true);
            codeProjectRepository.save(codeProject.get());
            return true;
        }
        return false;
    }
    /**
     * Method of putting CodeProject into scan queue by codeproject
     *
     * @param codeProject of CodeProject entity
     * @return true if scan is properly put into queue and false if there is no such CodeProject
     */

    public boolean putCodeProjectToQueue(CodeProject codeProject){
        try {
            codeProject.setInQueue(true);
            codeProjectRepository.save(codeProject);
            return true;
        } catch (Exception e){
            log.error("Exception occured during putting codeProject {} to queue", codeProject.getName());
        }
        return false;
    }

    /**
     * Calls Scanner API in order to get SAST Projects scanners
     * Assumes that there is only one scanner of SAST type
     *
     * @return List of SAST Projects from given scanner
     */
    public ResponseEntity<List<SASTProject>> getProjectFromSASTScanner() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        List<Scanner>  scanners = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true);
        if (scanners.size() < 2 && scanners.stream().findFirst().isPresent()){
            for (CodeScanClient csc : codeScanClients){
                if (csc.canProcessRequest(scanners.stream().findFirst().orElse(null))){
                    return new ResponseEntity<>(csc.getProjects(scanners.stream().findFirst().orElse(null)), HttpStatus.OK);
                }
            }
        }
        return new ResponseEntity<>(new ArrayList<>(), HttpStatus.OK);
    }

    /**
     * Method which execute SAST Scanner API in order to create Project entity on scanne side
     * Assumes that there is only one type of SAST scanner
     *
     * @param id of CodeProject which should be created on SAST Scanner
     * @param projectId id of Project entity
     * @return HttpStatus.CREATED when project is properly created or HttpStatus.PREDONDITION_FAILED when error occures
     */
    public ResponseEntity<Status> createProjectOnSASTScanner(Long id, Long projectId) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        Optional<Project> project = projectRepository.findById(projectId);
        Optional<CodeProject> codeProject = codeProjectRepository.findById(id);
        List<Scanner>  scanners = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true);
        if (project.isPresent()
                && codeProject.isPresent()
                && project.get().getId().equals(codeProject.get().getCodeGroup().getProject().getId())
                && scanners.size() < 2
                && scanners.stream().findFirst().isPresent()){
            for (CodeScanClient csc : codeScanClients){
                if (csc.canProcessRequest(scanners.stream().findFirst().orElse(null)) && csc.createProject(scanners.stream().findFirst().orElse(null), codeProject.get())){
                    return new ResponseEntity<>(new Status("created"), HttpStatus.CREATED);
                }
            }
        }
        return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
    }
}
