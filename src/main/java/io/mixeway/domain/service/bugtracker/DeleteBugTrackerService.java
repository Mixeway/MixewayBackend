package io.mixeway.domain.service.bugtracker;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.repository.BugTrackerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class DeleteBugTrackerService {
    private final BugTrackerRepository bugTrackerRepository;

    public void delete(BugTracker bugTracker){
        bugTrackerRepository.delete(bugTracker);
    }
}
