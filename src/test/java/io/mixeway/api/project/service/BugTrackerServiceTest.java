package io.mixeway.api.project.service;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.BugTrackerType;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.BugTrackerRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.bugtracker.FindBugTrackerService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.Principal;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class BugTrackerServiceTest {
    private final BugTrackerService bugTrackerService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final FindBugTrackerService findBugTrackerService;

    @Mock
    Principal principal;
    @MockBean
    GlobalScheduler globalScheduler;

    @MockBean
    NetworkScanScheduler networkScheduler;

    @MockBean
    CodeScheduler codeScheduler;

    @MockBean
    WebAppScheduler webAppScheduler;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("bug_tracker_service");
        User userToCreate = new User();
        userToCreate.setUsername("bug_tracker_service");
        userToCreate.setCommonName("bug_tracker_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    @Order(1)
    void getIssueTypes() {
        ResponseEntity<List<BugTrackerType>> listResponseEntity = bugTrackerService.getIssueTypes();
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size() > 0);
    }

    @Test
    @Order(3)
    void getBugTrackers() {
        Mockito.when(principal.getName()).thenReturn("bug_tracker_service");
        Project project = getOrCreateProjectService.getProjectId("bug_tracker_service","bug_tracker_service",principal);

        ResponseEntity<List<BugTracker>> listResponseEntity = bugTrackerService.getBugTrackers(project.getId(),principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size() > 0);

    }

    @Test
    @Order(2)
    void saveBugTracker() {
        Mockito.when(principal.getName()).thenReturn("bug_tracker_service");
        Project project = getOrCreateProjectService.getProjectId("bug_tracker_service","bug_tracker_service",principal);
        BugTracker bugTracker = new BugTracker();
        bugTracker.setBugTrackerType(findBugTrackerService.findAllTypes().stream().filter(bgt -> bgt.getName().equals("JIRA")).findFirst().get());
        bugTracker.setProject(project);
        bugTracker.setVulns("Network");
        bugTracker.setAutoStrategy("Manual");
        bugTracker.setUrl("https://jira");
        bugTracker.setUsername("user");
        bugTracker.setPassword("password");

        ResponseEntity<Status> statusResponseEntity = bugTrackerService.saveBugTracker(project.getId(),bugTracker, principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        List<BugTracker> bugTrackers = findBugTrackerService.findByProject(project);
        assertTrue(bugTrackers.size() > 0);
    }

    @Test
    @Order(5)
    void deleteBugTracker() {

        Mockito.when(principal.getName()).thenReturn("bug_tracker_service");
        Project project = getOrCreateProjectService.getProjectId("bug_tracker_service","bug_tracker_service",principal);
        List<BugTracker> bugTrackers = findBugTrackerService.findByProject(project);
        assertTrue(bugTrackers.size() > 0);
        BugTracker bugTrackerToDelete = bugTrackers.get(0);
        ResponseEntity<Status> statusResponseEntity = bugTrackerService.deleteBugTracker(project.getId(),bugTrackerToDelete.getId(),principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        bugTrackers = findBugTrackerService.findByProject(project);
        assertEquals(0, bugTrackers.size());

    }

}