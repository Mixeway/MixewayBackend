package io.mixeway.domain.service.bugtracker;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.BugTrackerType;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.BugTrackerRepository;
import io.mixeway.db.repository.BugTrackerTypeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindBugTrackerService {
    private final BugTrackerRepository bugTrackerRepository;
    private final BugTrackerTypeRepository bugTrackerTypeRepository;

    public List<BugTracker> findAll(){
        return bugTrackerRepository.findAll();
    }

    public List<BugTrackerType> findAllTypes(){
        return bugTrackerTypeRepository.findAll();
    }

    public List<BugTracker> findByProject(Project project){
        return bugTrackerRepository.findByProject(project);
    }

    public Optional<BugTracker> findByprojectAndVulnes(Project project, String vulns) {
        return bugTrackerRepository.findByProjectAndVulns(project,vulns);
    }

    public Optional<BugTracker> findById(Long bugTrackerId) {
        return bugTrackerRepository.findById(bugTrackerId);
    }
}
