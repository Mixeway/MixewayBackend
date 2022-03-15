package io.mixeway.scanmanager.service.code;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.cioperations.UpdateCiOperations;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.projectvulnerability.GetProjectVulnerabilitiesService;
import io.mixeway.domain.service.scanmanager.code.*;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.model.CodeAccessVerifier;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import io.mixeway.scanmanager.model.SASTRequestVerify;
import io.mixeway.scanmanager.service.CodeScanClient;
import io.mixeway.utils.*;
import io.mixeway.utils.ScannerType;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.codehaus.jettison.json.JSONException;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class CodeScanService {
    private final ProjectRepository projectRepository;
    private final CodeGroupRepository codeGroupRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final CodeAccessVerifier codeAccessVerifier;
    private final VaultHelper vaultHelper;
    private final List<CodeScanClient> codeScanClients;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final VulnTemplate vulnTemplate;
    private final UpdateCiOperations updateCiOperations;
    private final PermissionFactory permissionFactory;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final GetProjectVulnerabilitiesService getProjectVulnerabilitiesService;
    private final FindProjectService findProjectService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final FindCodeProjectService findCodeProjectService;
    private final FindCodeGroupService findCodeGroupService;
    private final UpdateCodeGroupService updateCodeGroupService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final CreateOrGetCodeGroupService createOrGetCodeGroupService;

    /**
     * Method for getting CodeVulns for given names
     *
     * @param projectId id of a Project entity
     * @param groupName name of CodeGroup entity
     * @param projectName name of CodeProject entity
     * @return List of a CodeVulns for a given CodeProject
     */
    public ResponseEntity<List<Vulnerability>> getResultsForProject(long projectId, String groupName, String projectName, Principal principal){
        Optional<Project> project = findProjectService.findProjectById(projectId);
        if (codeAccessVerifier.verifyPermissions(projectId,groupName,projectName,false).getValid() &&
                project.isPresent() &&
                permissionFactory.canUserAccessProject(principal, project.get())){
            CodeProject cp = createOrGetCodeProjectService.createOrGetCodeProjectWithGroupName(project.get(), groupName, projectName, Constants.CODE_DEFAULT_BRANCH);

            new ResponseEntity<>(getProjectVulnerabilitiesService.getProjectVulnerabilitiesForSource(cp, Constants.FORTIFY_NOT_AN_ISSUE), HttpStatus.OK);

        } else
            new ResponseEntity<List<ProjectVulnerability>>(new ArrayList<>(), HttpStatus.PRECONDITION_FAILED);


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
    public ResponseEntity<List<ProjectVulnerability>> getResultsForGroup(long projectId, String groupName){

        if (codeAccessVerifier.verifyPermissions(projectId,groupName,null, false).getValid()){
            Optional<Project> project = findProjectService.findProjectById(projectId);
            if (project.isPresent()) {
                Optional<CodeGroup> codeGroup = findCodeGroupService.findCodeGroup(project.get(), groupName);
                if (codeGroup.isPresent()){
                    List<ProjectVulnerability> projectVulnerabilities = getProjectVulnerabilitiesService.getProjectVulnerablitiesForCodeGroup(codeGroup.get(), Constants.FORTIFY_NOT_AN_ISSUE);
                    new ResponseEntity<>(projectVulnerabilities, HttpStatus.OK);
                }
            }

        } else
            new ResponseEntity<List<ProjectVulnerability>>(new ArrayList<>(), HttpStatus.PRECONDITION_FAILED);
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
    public ResponseEntity<Status> performScanFromScanManager(CodeScanRequestModel codeScanRequest, Principal principal) {
        if (codeScanRequest.getCiid() != null && !codeScanRequest.getCiid().equals("")){
            Optional<List<Project>> projects = projectRepository.findByCiid(codeScanRequest.getCiid());
            Project project;
            if (projects.isPresent() && projects.get().size()>0){
                project = projects.get().stream().findFirst().orElse(null);
            } else {
                project = getOrCreateProjectService.getProjectId(codeScanRequest.getCiid(),codeScanRequest.getProjectName(),principal);
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
    private String verifyAndCreateOrUpdateCodeProjectInformations(CodeScanRequestModel codeScanRequest, Project project) {
        String requestId;
        Optional<CodeGroup> codeGroup = findCodeGroupService.findCodeGroup(project, codeScanRequest.getCodeGroupName());

        if (codeGroup.isPresent()){
            Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(codeGroup.get(), codeScanRequest.getCodeProjectName());
            if (codeProject.isPresent()){
                updateCodeGroupService.updateCodeGroup(codeScanRequest, codeGroup.get());
                CodeProject updatedCodeProject = updateCodeProjectService.updateCodeProjectAndPutToQueue(codeScanRequest,codeProject.get());
                requestId = updatedCodeProject.getRequestId();
            } else {
                CodeGroup updatedCodeGroup = updateCodeGroupService.updateCodeGroup(codeScanRequest, codeGroup.get());
                CodeProject newCodeProject = createOrGetCodeProjectService.createCodeProject(codeScanRequest, updatedCodeGroup);
                newCodeProject = updateCodeProjectService.putCodeProjectToQueue(newCodeProject);
                requestId = newCodeProject.getRequestId();
            }
        } else {
            CodeGroup newCodeGroup = createOrGetCodeGroupService.createOrGetCodeGroup(codeScanRequest, project);
            CodeProject newCodeProject = createOrGetCodeProjectService.createCodeProject(codeScanRequest, newCodeGroup);
            newCodeProject = updateCodeProjectService.putCodeProjectToQueue(newCodeProject);
            requestId = newCodeProject.getRequestId();
        }
        return requestId;
    }

    /**
     * Method executed by scheduler to load Vulnerabilities Reports for each entity within database
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void schedulerReportSynchro() throws CertificateException, ParseException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, UnrecoverableKeyException, IOException, URISyntaxException {
        List<CodeGroup> groups = codeGroupRepository.findByVersionIdAllGreaterThan(0);
        log.info("SAST Offline synchronization Started");
        Optional<Scanner> sastScanner = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true).stream().findFirst();
        if (sastScanner.isPresent() && sastScanner.get().getStatus()) {
            for (CodeGroup group : groups) {
                List<ProjectVulnerability> tmpVulns = getOldVulnsForGroup(group);
                if (group.getVersionIdAll() > 0) {
                    for(CodeScanClient codeScanClient : codeScanClients){
                        if (codeScanClient.canProcessRequest(sastScanner.get())){
                            log.info("Starting loading SAST vulns for - {}", group.getName());
                            codeScanClient.loadVulnerabilities(sastScanner.get(),group,null,false,null,tmpVulns);
                            log.info("Loaded SAST vulns for - {}", group.getName());
                        }
                    }
                }
                List<Long> toRemove = vulnTemplate.projectVulnerabilityRepository.findByProjectAndVulnerabilitySource(group.getProject(), vulnTemplate.SOURCE_SOURCECODE).filter(v -> v.getStatus().getId().equals(vulnTemplate.STATUS_REMOVED.getId())).map(ProjectVulnerability::getId).collect(Collectors.toList());
                int removed =0;
                if (toRemove.size() > 0) {
                    removed = vulnTemplate.projectVulnerabilityRepository.deleteProjectVulnerabilityIn(toRemove);
                    log.info("Removed {} source code vulns for project {}", removed,group.getProject());
                }
            }
        }

        //vulnTemplate.projectVulnerabilityRepository.deleteByStatus(vulnTemplate.STATUS_REMOVED);
        log.info("SAST Offline synchronization completed");
    }

    /**
     * Method which put each codegroup in scan queue by Project.autoCodeScan = true
     */
    public void schedulerRunAutoScans() {
        log.info("Starting Fortify Scheduled Scans");
        //List<CodeGroup> groups = codeGroupRepository.findByAuto(true);
        List<Project> projects = projectRepository.findByAutoCodeScan(true);
        Optional<Scanner> sastScanner = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true).stream().findFirst();
        if ( sastScanner.isPresent() &&  sastScanner.get().getStatus()) {
            for (Project p : projects){
                for (CodeGroup cg : p.getCodes()){
                    for (CodeProject cp : cg.getProjects()){
                        cp.setInQueue(true);
                        codeProjectRepository.save(cp);
                    }
                }
            }
        }
    }

    /**
     * Method which is looking for CodeProject and CodeGroup with running = true
     * Verify if scan is done, and if so loads vulnerabilities
     */
    @Transactional
    public void getResultsForRunningScan() {
        Optional<Scanner> sastScanner = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true).stream().findFirst();
        if (sastScanner.isPresent()) {
            List<CodeProject> codeProjectsRunning =codeProjectRepository.findByRunning(true);
            for (CodeProject codeProject : codeProjectsRunning) {
                List<ProjectVulnerability> codeVulns = getOldVulnsForCodeProject(codeProject);
                for (CodeScanClient codeScanClient : codeScanClients) {
                    try {
                        if (codeScanClient.canProcessRequest(sastScanner.get()) && codeScanClient.isScanDone(null, codeProject)) {
                            codeScanClient.loadVulnerabilities(sastScanner.get(), codeProject.getCodeGroup(), null, true, codeProject, codeVulns);
                            log.info("Vulerabilities for codescan for {} with scope of {} loaded - single app", codeProject.getCodeGroup().getName(), codeProject.getName());
                            updateCiOperations.updateCiOperationsForSAST(codeProject);
                            codeProject.setRunning(false);
                            codeProject.getCodeGroup().setRunning(false);
                            codeProject.getCodeGroup().setRequestid(null);
                            codeProject.getCodeGroup().setScanid(null);
                            codeProject.getCodeGroup().setScope(null);
                            codeProject.setRisk(projectRiskAnalyzer.getCodeProjectRisk(codeProject) + projectRiskAnalyzer.getCodeProjectOpenSourceRisk(codeProject));
                            codeProject.getCodeGroup().setScanid(null);
                            codeGroupRepository.save(codeProject.getCodeGroup());
                            codeProjectRepository.save(codeProject);
                            if (codeProject.isEnableJira()) {
                                log.info("[CodeScan] Automatic integration with BugTracker enabled, proceeding...");
                                vulnTemplate.processBugTracking(codeProject, vulnTemplate.SOURCE_SOURCECODE);
                            }
                        }
                    } catch (Exception e){
                        log.error("[CodeScanService] There is exception of {} during verifying codeproject off {}", e.getLocalizedMessage(), codeProject.getName());
                        codeProject.getCodeGroup().setScanid(null);
                        codeProject.setRunning(false);
                        codeProject.setInQueue(false);
                        codeProjectRepository.save(codeProject);
                        codeProject.getCodeGroup().setRunning(false);
                        codeGroupRepository.save(codeProject.getCodeGroup());
                    }
                }
                vulnTemplate.projectVulnerabilityRepository.deleteByStatus(vulnTemplate.STATUS_REMOVED);
            }
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
//                for (CodeGroup cg : codeGroupRepository.findByInQueue(true)) {
//                    if (codeGroupRepository.countByRunning(true) == 0) {
//                        for (CodeScanClient codeScanClient : codeScanClients) {
//                            if (codeScanClient.canProcessRequest(cg)) {
//                                log.info("Ready to scan [scope ALL] {}, taking it from the queue", cg.getName());
//                                cg.setInQueue(false);
//                                codeGroupRepository.saveAndFlush(cg);
//                                codeScanClient.runScan(cg, null);
//                            }
//                        }
//                    }
//                }

            } catch (IndexOutOfBoundsException ex) {
                log.debug("Fortify configuration missing");
            } catch (HttpClientErrorException ex) {
                log.warn("HttpClientErrorException with code [{}] during cloud scan job synchro ", ex.getStatusCode().toString());
            } catch (ParseException | JSONException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException e) {
                log.warn("Exception came up during running scan {}", e.getLocalizedMessage());
                e.printStackTrace();
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
        else return !cp.getCodeGroup().isRunning();
    }


    /**
     * Getting old vulnerabilities for CodeGroup and set status to removed
     *
     * @param group codeGroup to delate vulns for
     * @return List of deleted vulns to set proper status
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public List<ProjectVulnerability> getOldVulnsForGroup(CodeGroup group) {
        List<ProjectVulnerability> tmpVulns = new ArrayList<>();
        if (group.getHasProjects()) {
            for (CodeProject cp : group.getProjects()) {
                tmpVulns.addAll(vulnTemplate.projectVulnerabilityRepository.findByCodeProject(cp));

            }
        } else{
            tmpVulns.addAll(vulnTemplate.projectVulnerabilityRepository.findByCodeProjectIn(new ArrayList<>(group.getProjects())));
        }
        if (tmpVulns.size()>0)
            vulnTemplate.projectVulnerabilityRepository.updateVulnState(tmpVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList()),
                    vulnTemplate.STATUS_REMOVED.getId());
        return tmpVulns;
    }
    /**
     * Getting old vulnerabilities for CodeProject, and set status to removed
     *
     * @param codeProject CodeProject to delate vulns for
     * @return List of deleted vulns to set proper status
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    List<ProjectVulnerability> getOldVulnsForCodeProject(CodeProject codeProject){
        List<ProjectVulnerability> codeVulns = vulnTemplate.projectVulnerabilityRepository.findByCodeProjectAndVulnerabilitySource(codeProject, vulnTemplate.SOURCE_SOURCECODE).collect(Collectors.toList());
        if (codeVulns.size() > 0) {
            vulnTemplate.projectVulnerabilityRepository.updateVulnState(codeVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList()),
                    vulnTemplate.STATUS_REMOVED.getId());
            codeVulns.forEach(pv -> pv.setStatus(vulnTemplate.STATUS_REMOVED));
        }

        return codeVulns;
    }
    /**
     * Getting old vulnerabilities for CodeProject, and set status to removed
     *
     * @param codeProject CodeProject to delate vulns for
     * @return List of deleted vulns to set proper status
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    List<ProjectVulnerability> getOldVulnsForCodeProjectAndSource(CodeProject codeProject, VulnerabilitySource vulnerabilitySource){
        List<ProjectVulnerability> codeVulns = vulnTemplate.projectVulnerabilityRepository.findByCodeProjectAndVulnerabilitySource(codeProject, vulnerabilitySource).collect(Collectors.toList());
        if (codeVulns.size() > 0) {
            vulnTemplate.projectVulnerabilityRepository.updateVulnState(codeVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList()),
                    vulnTemplate.STATUS_REMOVED.getId());
            codeVulns.forEach(pv -> pv.setStatus(vulnTemplate.STATUS_REMOVED));
        }

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
     * @param principal principal who is executing the request
     * @return ResponseEntity with HttpStatus.OK if scan is properly executed HttpStatus.PREDONDITION_FAILED if there is a problem
     */
    public ResponseEntity<Status> codescanrunSelectedCodeProjectsScan(Long id, List<RunScanForCodeProject> runScanForCodeProjects, Principal principal) {
        try {
            Optional<Project> project = projectRepository.findById(id);
            if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
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
                log.info("{} - Run SAST scan for {} - scope partial", LogUtil.prepare(principal.getName()), LogUtil.prepare(project.get().getName()));

                return new ResponseEntity<>(HttpStatus.OK);
            }
        } catch (IndexOutOfBoundsException | ParseException | JSONException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException ioob){
            log.error("Problem with scanning selected projects reason is {}", ioob.getLocalizedMessage());
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    /**
     * Method of putting CodeProject into scan queue by codeproject.id
     *
     * @param id of CodeProject entity
     * @return true if scan is properly put into queue and false if there is no such CodeProject
     */
    public boolean putCodeProjectToQueue(Long id, Principal principal) {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(id);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getCodeGroup().getProject())){
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
     * @param principal
     * @return HttpStatus.CREATED when project is properly created or HttpStatus.PREDONDITION_FAILED when error occures
     */
    public ResponseEntity<Status> createProjectOnSASTScanner(Long id, Long projectId, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        Optional<Project> project = projectRepository.findById(projectId);
        Optional<CodeProject> codeProject = codeProjectRepository.findById(id);
        List<Scanner>  scanners = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true);
        if (project.isPresent()
                && permissionFactory.canUserAccessProject(principal, project.get())
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

    /**
     * Loading vulns from Mixeway scanner push to db
     * @param codeProject project with vulns
     * @param sastVulns list of vulns
     */
    @Transactional
    @Modifying
    public void loadVulnsFromCICDToCodeProject(CodeProject codeProject, List<VulnerabilityModel> sastVulns, ScannerType scannerType) {
        VulnerabilitySource vulnerabilitySource = null;
        if (scannerType.equals(ScannerType.SAST)){
            vulnerabilitySource = vulnTemplate.SOURCE_SOURCECODE;
        } else if (scannerType.equals(ScannerType.GITLEAKS)){
            vulnerabilitySource = vulnTemplate.SOURCE_GITLEAKS;
        }
        List<ProjectVulnerability> oldVulnsForCodeProject = getOldVulnsForCodeProjectAndSource(codeProject,vulnerabilitySource);
        List<ProjectVulnerability> vulnToPersist = new ArrayList<>();
        for (VulnerabilityModel vulnerabilityModel : sastVulns){
            Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(vulnerabilityModel.getName());

            ProjectVulnerability projectVulnerability = new ProjectVulnerability(codeProject,codeProject,vulnerability, vulnerabilityModel.getDescription(),null,
                    vulnerabilityModel.getSeverity(),null,vulnerabilityModel.getFilename()+":"+vulnerabilityModel.getLine(),
                    "", vulnerabilitySource, null );

            vulnToPersist.add(projectVulnerability);
        }
        vulnTemplate.vulnerabilityPersistList(oldVulnsForCodeProject, vulnToPersist);

        removeOldVulns(codeProject);

        vulnTemplate.projectVulnerabilityRepository.flush();
        log.info("[CICD] SourceCode - Loading Vulns for {} completed type of {}", codeProject.getName(), scannerType);
    }


    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void removeOldVulns(CodeProject codeProject) {
        List<ProjectVulnerability> toRemove = vulnTemplate.projectVulnerabilityRepository.findByCodeProjectAndVulnerabilitySource(codeProject, vulnTemplate.SOURCE_SOURCECODE).filter(v -> v.getStatus().getId().equals(vulnTemplate.STATUS_REMOVED.getId())).collect(Collectors.toList());
        vulnTemplate.projectVulnerabilityRepository.deleteAll(toRemove);
    }
}
