package io.mixeway.domain.service.bugtracker;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.BugTrackerType;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.BugTrackerTypeRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CreateBugTrackerTest {
    private final CreateBugTracker createBugTracker;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final BugTrackerTypeRepository bugTrackerTypeRepository;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("create_bt");
        User userToCreate = new User();
        userToCreate.setUsername("create_bt");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void save() {
        Mockito.when(principal.getName()).thenReturn("create_bt");
        Project project = getOrCreateProjectService.getProjectId("create_bt","create_bt",principal);
        BugTracker bugTracker = new BugTracker();
        bugTracker.setUrl("https://test");
        bugTracker.setBugTrackerType(bugTrackerTypeRepository.findByName("JIRA"));
        BugTracker bugTracker1 = createBugTracker.save(bugTracker,project);
        assertNotNull(bugTracker1);
    }
}