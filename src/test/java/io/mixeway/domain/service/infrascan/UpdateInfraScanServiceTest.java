package io.mixeway.domain.service.infrascan;

import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.InfraScanRepository;
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
class UpdateInfraScanServiceTest {
    private final UpdateInfraScanService updateInfraScanService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final InfraScanRepository infraScanRepository;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("update_infra_scan");
        User userToCreate = new User();
        userToCreate.setUsername("update_infra_scan");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }


    @Test
    void changeStateForRunningScan() {
        Mockito.when(principal.getName()).thenReturn("update_infra_scan");
        Project project = getOrCreateProjectService.getProjectId("update_infra_scan","update_infra_scan", principal);
        InfraScan infraScan = new InfraScan();
        infraScan.setProject(project);
        infraScan = infraScanRepository.save(infraScan);
        updateInfraScanService.changeStateForRunningScan(infraScan);
        infraScan = infraScanRepository.findById(infraScan.getId()).get();
        assertNotNull(infraScan);
        assertTrue(infraScan.getRunning());
        assertFalse(infraScan.getInQueue());
    }
}