package io.mixeway.scanmanager.service.bugtracking;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.utils.Status;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.ResponseEntity;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

public interface BugTracking {
    String createIssue(String title, String description, BugTracker bugTracker) throws URISyntaxException;
    public Boolean canIssueTicket(boolean mode, ProjectVulnerability vulnerability, String issueStrategy);
    void closeIssue(String ticketId, BugTracker bugTracker) throws URISyntaxException;
    <T extends JpaRepository> ResponseEntity<Status> processRequest(T o, Optional<ProjectVulnerability> entity, BugTracker bugTracker, Project project, String vulnType, String principal, Boolean manual) throws URISyntaxException;
    <T extends JpaRepository> ResponseEntity<Status> processRequestMultiVuln(T o, List<ProjectVulnerability> entity, BugTracker bugTracker, Project project, String vulnType, String principal, Boolean manual) throws URISyntaxException;
    boolean canProcessRequest(BugTracker bugTracker);
}
