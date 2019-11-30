package io.mixeway.rest.project.service;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import io.mixeway.plugins.bugtracker.BugTracking;
import io.mixeway.pojo.Status;

import java.net.URISyntaxException;
import java.util.*;

@Service
public class BugTrackerService {
    private static final Logger log = LoggerFactory.getLogger(BugTrackerService.class);
    private final BugTrackerTypeRepository bugTrackerTypeRepository;
    private final BugTrackerRepository bugTrackerRepository;
    private final VaultOperations vaultOperations;
    private final ProjectRepository projectRepository;
    private final InfrastructureVulnRepository infrastructureVulnRepository;
    private final WebAppVulnRepository webAppVulnRepository;
    private final CodeVulnRepository codeVulnRepository;
    private final List<BugTracking> bugTrackings;
    private final SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;
    private List<String> types = Arrays.asList("infra", "code", "webapp","opensource");
    private List<String> strategy = Arrays.asList("Manual", "High", "Medium","Low");
    @Autowired
    BugTrackerService(BugTrackerTypeRepository bugTrackerTypeRepository, BugTrackerRepository bugTrackerRepository,
                      VaultOperations vaultOperations, ProjectRepository projectRepository, List<BugTracking> bugTrackings,
                      InfrastructureVulnRepository infrastructureVulnRepository, WebAppVulnRepository webAppVulnRepository,
                      CodeVulnRepository codeVulnRepository, SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository){
        this.bugTrackerTypeRepository = bugTrackerTypeRepository;
        this.vaultOperations = vaultOperations;
        this.projectRepository = projectRepository;
        this.infrastructureVulnRepository = infrastructureVulnRepository;
        this.webAppVulnRepository = webAppVulnRepository;
        this.codeVulnRepository = codeVulnRepository;
        this.softwarePacketVulnerabilityRepository = softwarePacketVulnerabilityRepository;
        this.bugTrackerRepository = bugTrackerRepository;
        this.bugTrackings = bugTrackings;
    }
    public ResponseEntity<List<BugTrackerType>> getIssueTypes() {
        return new ResponseEntity<>(bugTrackerTypeRepository.findAll(), HttpStatus.OK);
    }

    public ResponseEntity<List<BugTracker>> getBugTrackers(Long id) {
        Optional<Project> project = projectRepository.findById(id);
        return project.map(value -> new ResponseEntity<>(bugTrackerRepository.findByProject(value), HttpStatus.OK)).orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    public ResponseEntity<Status> saveBugTracker(Long id, BugTracker bugTracker,String name) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && types.contains(bugTracker.getVulns()) && strategy.contains(bugTracker.getAutoStrategy()) &&
                !bugTrackerRepository.findByProjectAndVulns(project.get(),bugTracker.getVulns()).isPresent()) {
            String uuidPass = UUID.randomUUID().toString();
            Map<String, String> upassMap = new HashMap<>();
            upassMap.put("password", bugTracker.getPassword());
            vaultOperations.write("secret/"+uuidPass, upassMap);
            bugTracker.setProject(project.get());
            bugTracker.setPassword(uuidPass);
            bugTrackerRepository.save(bugTracker);
            log.info("{} - Created new BugTracker for {} vulns {}", name, bugTracker.getProject().getName(), bugTracker.getVulns());
            return new ResponseEntity<>(new Status("OK"), HttpStatus.CREATED);
        } else
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    public ResponseEntity<Status> deleteBugTracker(Long id, Long bugTrackerId, String name) {
        Optional<Project> project = projectRepository.findById(id);
        Optional<BugTracker> bugTracker = bugTrackerRepository.findById(bugTrackerId);
        if (project.isPresent() && bugTracker.isPresent() && bugTracker.get().getProject().equals(project.get())){
            bugTrackerRepository.delete(bugTracker.get());
            log.info("{} - Deleted BugTracker for {} vulns {}", name, bugTracker.get().getProject().getName(), bugTracker.get().getVulns());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<Status> issueTicket(Long id, String vulnType, Long vulnId, String name) throws URISyntaxException {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()) {
            Optional<BugTracker> bugTracker = bugTrackerRepository.findByProjectAndVulns(project.get(),vulnType);
            if (bugTracker.isPresent() && vulnType.equals("infra")) {
                Optional<InfrastructureVuln> infrastructureVuln = infrastructureVulnRepository.findById(vulnId);
                for (BugTracking bugTracking : bugTrackings){
                    if (bugTracking.canProcessRequest(bugTracker.get())){
                        return bugTracking.processRequest(infrastructureVulnRepository, infrastructureVuln,bugTracker.get(), project.get(), vulnType, name, true);
                    }
                }
            } else if (bugTracker.isPresent() &&vulnType.equals("webapp")) {
                Optional<WebAppVuln> webAppVuln = webAppVulnRepository.findById(vulnId);
                for (BugTracking bugTracking : bugTrackings){
                    if (bugTracking.canProcessRequest(bugTracker.get())){
                        return bugTracking.processRequest(webAppVulnRepository, webAppVuln,bugTracker.get(), project.get(), vulnType, name, true);
                    }
                }
            } else if (bugTracker.isPresent() &&vulnType.equals("code")) {
                Optional<CodeVuln> codeVuln = codeVulnRepository.findById(vulnId);
                for (BugTracking bugTracking : bugTrackings){
                    if (bugTracking.canProcessRequest(bugTracker.get())){
                        return bugTracking.processRequest(codeVulnRepository, codeVuln,bugTracker.get(), project.get(), vulnType, name, true);
                    }
                }
            } else if (bugTracker.isPresent() &&vulnType.equals("opensource")) {
                Optional<SoftwarePacketVulnerability> softwarePacketVulnerability = softwarePacketVulnerabilityRepository.findById(id);
                for (BugTracking bugTracking : bugTrackings){
                    if (bugTracking.canProcessRequest(bugTracker.get())){
                        return bugTracking.processRequest(softwarePacketVulnerabilityRepository, softwarePacketVulnerability,bugTracker.get(), project.get(), vulnType, name, true);
                    }
                }
            } else {
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);

    }

}
