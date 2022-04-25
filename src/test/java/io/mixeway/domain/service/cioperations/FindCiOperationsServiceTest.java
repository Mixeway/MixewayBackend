package io.mixeway.domain.service.cioperations;

import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.api.protocol.cioperations.InfoScanPerformed;
import io.mixeway.db.entity.CiOperations;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FindCiOperationsServiceTest {
    private final FindCiOperationsService findCiOperationsService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final CreateCiOperationsService createCiOperationsService;
    private final CiOperationsRepository ciOperationsRepository;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("find_ci");
        User userToCreate = new User();
        userToCreate.setUsername("find_ci");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        Project project = getOrCreateProjectService.getProjectId("finc_ci", "find_ci", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"find_ci", "master");
        InfoScanPerformed infoScanPerformed = InfoScanPerformed.builder()
                .commitId("commit")
                .codeProjectId(codeProject.getId())
                .branch("master")
                .build();
        CiOperations ciOperations = createCiOperationsService.create(codeProject, infoScanPerformed);
        ciOperations.setResult("Ok");
        ciOperationsRepository.save(ciOperations);
    }

    @Test
    void getVulnTrendData() {
        Mockito.when(principal.getName()).thenReturn("find_ci");
        List<Project> projectList = new ArrayList<>();
        projectList.add(getOrCreateProjectService.getProjectId("finc_ci", "find_ci", principal));
        List<OverAllVulnTrendChartData> overAllVulnTrendChartData = findCiOperationsService.getVulnTrendData(projectList);
        assertTrue(overAllVulnTrendChartData.size() > 0);

    }

    @Test
    void countByResultAndProject() {
        Mockito.when(principal.getName()).thenReturn("find_ci");
        List<Project> projectList = new ArrayList<>();
        projectList.add(getOrCreateProjectService.getProjectId("finc_ci", "find_ci", principal));
        Long okResults = findCiOperationsService.countByResultAndProject("Ok",projectList);
        assertEquals(1, okResults);
    }

    @Test
    void findByProjects() {

        Mockito.when(principal.getName()).thenReturn("find_ci");
        List<Project> projectList = new ArrayList<>();
        projectList.add(getOrCreateProjectService.getProjectId("finc_ci", "find_ci", principal));

        List<CiOperations> ciOperations = findCiOperationsService.findByProjects(projectList);
        assertTrue(ciOperations.size()>0);
    }

    @Test
    void findByCodeProjectAndCommitId() {
        Mockito.when(principal.getName()).thenReturn("find_ci");
        Project project = getOrCreateProjectService.getProjectId("finc_ci", "find_ci", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"find_ci", "master");
        Optional<CiOperations> ciOperations = findCiOperationsService.findByCodeProjectAndCommitId(codeProject,"commit");
        assertTrue(ciOperations.isPresent());

    }

    @Test
    void findTop20() {
        Mockito.when(principal.getName()).thenReturn("find_ci");
        Project project = getOrCreateProjectService.getProjectId("finc_ci", "find_ci", principal);
        List<CiOperations> ciOperations = findCiOperationsService.findTop20(project);
        assertTrue(ciOperations.size()>0);
    }
}