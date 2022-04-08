package io.mixeway.domain.service.bugtracker;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.BugTrackerType;
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
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FindBugTrackerServiceTest {
    private final FindBugTrackerService findBugTrackerService;
    private final UserRepository userRepository;
    private final CreateBugTracker createBugTracker;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final BugTrackerTypeRepository bugTrackerTypeRepository;

    @Mock
    Principal principal;
    @BeforeAll
    private void setUpTest(){
        Mockito.when(principal.getName()).thenReturn("find_bt");
        User user = new User();
        user.setUsername("find_bt");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
    }

    @Test
    void findAll() {
        Mockito.when(principal.getName()).thenReturn("find_bt");
        BugTracker bugTracker = new BugTracker();
        Project project = getOrCreateProjectService.getProjectId("bt_find","bt_find",principal);
        bugTracker.setUrl("https://test");
        bugTracker.setBugTrackerType(bugTrackerTypeRepository.findByName("JIRA"));
        createBugTracker.save(bugTracker,project);
        assertTrue(findBugTrackerService.findAll().size() > 0);


    }

    @Test
    void findAllTypes() {
        Mockito.when(principal.getName()).thenReturn("find_bt");

        List<BugTrackerType> bugTrackerTypeList = findBugTrackerService.findAllTypes();
        assertTrue(bugTrackerTypeList.size()>0);
    }

    @Test
    void findByProject() {
        Mockito.when(principal.getName()).thenReturn("find_bt");
        Project project = getOrCreateProjectService.getProjectId("bt_find2","bt_find2",principal);
        BugTracker bugTracker = new BugTracker();
        bugTracker.setUrl("https://test");
        bugTracker.setBugTrackerType(bugTrackerTypeRepository.findByName("JIRA"));
        createBugTracker.save(bugTracker,project);
        List<BugTracker> bugTrackerList = findBugTrackerService.findByProject(project);
        assertTrue(bugTrackerList.size()>0);
    }

    @Test
    void findByprojectAndVulnes() {
        Mockito.when(principal.getName()).thenReturn("find_bt");
        Project project = getOrCreateProjectService.getProjectId("bt_find3","bt_find3",principal);
        BugTracker bugTracker = new BugTracker();
        bugTracker.setUrl("https://test");
        bugTracker.setVulns("code");
        bugTracker.setBugTrackerType(bugTrackerTypeRepository.findByName("JIRA"));
        createBugTracker.save(bugTracker,project);
        Optional<BugTracker> bugTrackers = findBugTrackerService.findByprojectAndVulnes(project,"code");
        assertTrue(bugTrackers.isPresent());
    }

    @Test
    void findById() {
        Mockito.when(principal.getName()).thenReturn("find_bt");
        Project project = getOrCreateProjectService.getProjectId("bt_find4","bt_find4",principal);
        BugTracker bugTracker = new BugTracker();
        bugTracker.setUrl("https://test");
        bugTracker.setVulns("code");
        bugTracker.setBugTrackerType(bugTrackerTypeRepository.findByName("JIRA"));
        createBugTracker.save(bugTracker,project);
        BugTracker bugTracker1 = findBugTrackerService.findByProject(project).get(0);
        assertTrue(bugTracker1 != null);

        Optional<BugTracker> lookedFor = findBugTrackerService.findById(bugTracker1.getId());
        assertTrue(lookedFor.isPresent());
        lookedFor = findBugTrackerService.findById(66L);
        assertFalse(lookedFor.isPresent());

    }
}