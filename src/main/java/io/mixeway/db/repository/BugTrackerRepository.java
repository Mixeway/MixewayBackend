package io.mixeway.db.repository;

import io.mixeway.db.entity.BugTracker;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import io.mixeway.db.entity.Project;

import java.util.List;
import java.util.Optional;

@Repository
public interface BugTrackerRepository extends JpaRepository <BugTracker, Long> {
    List<BugTracker> findByProject(Project project);
    Optional<BugTracker> findByProjectAndVulns(Project project, String vulns);
}
