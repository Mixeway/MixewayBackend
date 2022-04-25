package io.mixeway.api.project.controller;

import io.mixeway.api.project.service.BugTrackerService;
import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.BugTrackerType;
import io.mixeway.utils.Status;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.URISyntaxException;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/v2/api/show/project")
public class BugTrackerController {
    private final BugTrackerService bugTrackerService;
    BugTrackerController(BugTrackerService bugTrackerService){
        this.bugTrackerService = bugTrackerService;
    }

    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/getbugtrackertypes")
    public ResponseEntity<List<BugTrackerType>> getIssueTypes() {
        return bugTrackerService.getIssueTypes();
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @GetMapping(value = "/{id}/getbugtrackers")
    public ResponseEntity<List<BugTracker>> getBugTrackers(@PathVariable("id")Long id, Principal principal) {
        return bugTrackerService.getBugTrackers(id, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/getbugtrackers")
    public ResponseEntity<Status> saveBugTracker(@PathVariable("id")Long id, @RequestBody BugTracker bugTracker, Principal principal) {
        return bugTrackerService.saveBugTracker(id, bugTracker,principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/{id}/getbugtrackers/{bugtracker}")
    public ResponseEntity<Status> delteBugTracker(@PathVariable("id")Long id, @PathVariable("bugtracker")Long bugTrackerId, Principal principal) {
        return bugTrackerService.deleteBugTracker(id, bugTrackerId, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/issueticket/{vulntype}/{vulnId}")
    public ResponseEntity<Status> saveBugTracker(@PathVariable("id")Long id, @PathVariable("vulntype") String vulnType,
            @PathVariable("vulnId") Long vulnId, Principal principal) throws URISyntaxException {
        return bugTrackerService.issueTicket(id, vulnType, vulnId,principal);
    }
}
