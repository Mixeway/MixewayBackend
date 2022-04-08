package io.mixeway.domain.service.bugtracker;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.BugTrackerRepository;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class CreateBugTracker {
    private final BugTrackerRepository bugTrackerRepository;
    private final VaultHelper vaultHelper;

    public BugTracker save(BugTracker bugTracker, Project project){
        String uuidPass = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(bugTracker.getPassword(),uuidPass)){
            bugTracker.setPassword(uuidPass);
        }
        bugTracker.setProject(project);
        bugTrackerRepository.save(bugTracker);
        return bugTracker;
    }
}
