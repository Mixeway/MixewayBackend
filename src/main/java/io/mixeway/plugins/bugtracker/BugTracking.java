package io.mixeway.plugins.bugtracker;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.ResponseEntity;
import io.mixeway.pojo.Status;
import io.mixeway.pojo.Vulnerability;

import java.net.URISyntaxException;
import java.util.Optional;

public interface BugTracking {
    String createIssue(String title, String description, BugTracker bugTracker) throws URISyntaxException;
    <V extends Vulnerability> Boolean canIssueTicket(boolean mode, V vulnerability, String issueStrategy);
    void closeIssue(String ticketId, BugTracker bugTracker) throws URISyntaxException;
    <T extends JpaRepository, V extends Vulnerability> ResponseEntity<Status> processRequest(T o, Optional<V> entity, BugTracker bugTracker, Project project, String vulnType, String principal, Boolean manual) throws URISyntaxException;
    boolean canProcessRequest(BugTracker bugTracker);
}
