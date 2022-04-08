package io.mixeway.domain.service.bugtracker;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.BugTrackerTypeRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
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
class DeleteBugTrackerServiceTest {
    private final FindBugTrackerService findBugTrackerService;
    private final UserRepository userRepository;
    private final CreateBugTracker createBugTracker;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final BugTrackerTypeRepository bugTrackerTypeRepository;
    private final DeleteBugTrackerService deleteBugTrackerService;

    @Mock
    Principal principal;
    @BeforeAll
    private void setUpTest(){
        Mockito.when(principal.getName()).thenReturn("delete_bt");
        User user = new User();
        user.setUsername("delete_bt");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
    }

    @Test
    void delete() {
        Mockito.when(principal.getName()).thenReturn("delete_bt");
        BugTracker bugTracker = new BugTracker();
        Project project = getOrCreateProjectService.getProjectId("bt_delete","bt_delete",principal);
        bugTracker.setUrl("https://test");
        bugTracker.setBugTrackerType(bugTrackerTypeRepository.findByName("JIRA"));
        createBugTracker.save(bugTracker,project);
        int oldSize = findBugTrackerService.findAll().size();
        deleteBugTrackerService.delete(bugTracker);
        assertEquals(oldSize-1, findBugTrackerService.findAll().size());
    }
}