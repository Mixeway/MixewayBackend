package io.mixeway.api.project.service;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.BugTrackerType;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.domain.service.bugtracker.CreateBugTracker;
import io.mixeway.domain.service.bugtracker.DeleteBugTrackerService;
import io.mixeway.domain.service.bugtracker.FindBugTrackerService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.service.bugtracking.BugTracking;
import io.mixeway.utils.LogUtil;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.Status;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
@Log4j2
@RequiredArgsConstructor
public class BugTrackerService {
    private final VaultHelper vaultHelper;
    private final List<BugTracking> bugTrackings;
    private final VulnTemplate vulnTemplate;
    private final PermissionFactory permissionFactory;
    private final FindBugTrackerService findBugTrackerService;
    private final FindProjectService findProjectService;
    private final CreateBugTracker createBugTracker;
    private final DeleteBugTrackerService deleteBugTrackerService;

    private List<String> types = Arrays.asList("Network", "WebApplication", "SourceCode","OpenSource");
    private List<String> strategy = Arrays.asList("Manual", "High", "Medium","Low");


    public ResponseEntity<List<BugTrackerType>> getIssueTypes() {
        return new ResponseEntity<>(findBugTrackerService.findAllTypes(), HttpStatus.OK);
    }

    public ResponseEntity<List<BugTracker>> getBugTrackers(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())) {
            return project.map(value -> new ResponseEntity<>(findBugTrackerService.findByProject(value), HttpStatus.OK)).orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<Status> saveBugTracker(Long id, BugTracker bugTracker, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && types.contains(bugTracker.getVulns()) && strategy.contains(bugTracker.getAutoStrategy()) &&
                !findBugTrackerService.findByprojectAndVulnes(project.get(),bugTracker.getVulns()).isPresent() && permissionFactory.canUserAccessProject(principal,project.get())) {
            createBugTracker.save(bugTracker,project.get());
            log.info("{} - Created new BugTracker for {} vulns {}", principal.getName(), LogUtil.prepare(bugTracker.getProject().getName()), LogUtil.prepare(bugTracker.getVulns()));
            return new ResponseEntity<>(new Status("OK"), HttpStatus.CREATED);
        } else
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    public ResponseEntity<Status> deleteBugTracker(Long id, Long bugTrackerId, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        Optional<BugTracker> bugTracker = findBugTrackerService.findById(bugTrackerId);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get()) && bugTracker.isPresent() && bugTracker.get().getProject().equals(project.get())){
            deleteBugTrackerService.delete(bugTracker.get());
            log.info("{} - Deleted BugTracker for {} vulns {}", principal.getName(), bugTracker.get().getProject().getName(), bugTracker.get().getVulns());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ResponseEntity<Status> issueTicket(Long id, String vulnType, Long vulnId, Principal principal) throws URISyntaxException {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            Optional<BugTracker> bugTracker = findBugTrackerService.findByprojectAndVulnes(project.get(),vulnType);
            Optional<ProjectVulnerability> projectVulnerability = vulnTemplate.projectVulnerabilityRepository.findById(vulnId);
            if (bugTracker.isPresent() && projectVulnerability.isPresent()) {
                for (BugTracking bugTracking : bugTrackings) {
                    if (bugTracking.canProcessRequest(bugTracker.get())) {
                        return bugTracking.processRequest(vulnTemplate.projectVulnerabilityRepository, projectVulnerability, bugTracker.get(), project.get(), vulnType, principal.getName(), true);
                    }
                }
            }
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);

    }

}
