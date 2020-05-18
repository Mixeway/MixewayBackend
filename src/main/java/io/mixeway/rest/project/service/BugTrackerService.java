package io.mixeway.rest.project.service;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.VaultHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import io.mixeway.integrations.bugtracker.BugTracking;
import io.mixeway.pojo.Status;

import java.net.URISyntaxException;
import java.util.*;

@Service
public class BugTrackerService {
    private static final Logger log = LoggerFactory.getLogger(BugTrackerService.class);
    private final BugTrackerTypeRepository bugTrackerTypeRepository;
    private final BugTrackerRepository bugTrackerRepository;
    private final VaultHelper vaultHelper;
    private final ProjectRepository projectRepository;
    private final List<BugTracking> bugTrackings;
    private final VulnTemplate vulnTemplate;
    private List<String> types = Arrays.asList("infra", "code", "webapp","opensource");
    private List<String> strategy = Arrays.asList("Manual", "High", "Medium","Low");

    BugTrackerService(BugTrackerTypeRepository bugTrackerTypeRepository, BugTrackerRepository bugTrackerRepository,
                      VaultHelper vaultHelper, ProjectRepository projectRepository, List<BugTracking> bugTrackings,
                      VulnTemplate vulnTemplate){
        this.bugTrackerTypeRepository = bugTrackerTypeRepository;
        this.vaultHelper = vaultHelper;
        this.projectRepository = projectRepository;
        this.bugTrackerRepository = bugTrackerRepository;
        this.bugTrackings = bugTrackings;
        this.vulnTemplate = vulnTemplate;
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
            if (vaultHelper.savePassword(bugTracker.getPassword(),uuidPass)){
                bugTracker.setPassword(uuidPass);
            }
            bugTracker.setProject(project.get());
            bugTrackerRepository.save(bugTracker);
            log.info("{} - Created new BugTracker for {} vulns {}", name, LogUtil.prepare(bugTracker.getProject().getName()), LogUtil.prepare(bugTracker.getVulns()));
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

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ResponseEntity<Status> issueTicket(Long id, String vulnType, Long vulnId, String name) throws URISyntaxException {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()) {
            Optional<BugTracker> bugTracker = bugTrackerRepository.findByProjectAndVulns(project.get(),vulnType);
            Optional<ProjectVulnerability> projectVulnerability = vulnTemplate.projectVulnerabilityRepository.findById(vulnId);
            if (bugTracker.isPresent() && projectVulnerability.isPresent()) {
                for (BugTracking bugTracking : bugTrackings) {
                    if (bugTracking.canProcessRequest(bugTracker.get())) {
                        return bugTracking.processRequest(vulnTemplate.projectVulnerabilityRepository, projectVulnerability, bugTracker.get(), project.get(), vulnType, name, true);
                    }
                }
            }
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);

    }

}
