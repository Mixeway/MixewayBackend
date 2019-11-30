package io.mixeway.rest.project.controller;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.BugTrackerType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import io.mixeway.pojo.Status;
import io.mixeway.rest.project.service.BugTrackerService;

import java.net.URISyntaxException;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/v2/api/show/project")
public class BugTrackerController {
    private final BugTrackerService bugTrackerService;
    @Autowired
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
    public ResponseEntity<List<BugTracker>> getBugTrackers(@PathVariable("id")Long id) {
        return bugTrackerService.getBugTrackers(id);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/getbugtrackers")
    public ResponseEntity<Status> saveBugTracker(@PathVariable("id")Long id, @RequestBody BugTracker bugTracker, Principal principal) {
        return bugTrackerService.saveBugTracker(id, bugTracker,principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @DeleteMapping(value = "/{id}/getbugtrackers/{bugtracker}")
    public ResponseEntity<Status> saveBugTracker(@PathVariable("id")Long id, @PathVariable("bugtracker")Long bugTrackerId, Principal principal) {
        return bugTrackerService.deleteBugTracker(id, bugTrackerId, principal.getName());
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PutMapping(value = "/{id}/issueticket/{vulntype}/{vulnId}")
    public ResponseEntity<Status> saveBugTracker(@PathVariable("id")Long id, @PathVariable("vulntype") String vulnType,
            @PathVariable("vulnId") Long vulnId, Principal principal) throws URISyntaxException {
        return bugTrackerService.issueTicket(id, vulnType, vulnId,principal.getName());
    }
}
