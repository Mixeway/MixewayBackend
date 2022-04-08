package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
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
class OperateOnCodeProjectTest {
    private final OperateOnCodeProject operateOnCodeProject;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("operate_cp");
        User userToCreate = new User();
        userToCreate.setUsername("operate_cp");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void canScanCodeProject() {
        Mockito.when(principal.getName()).thenReturn("operate_cp");
        Project project = getOrCreateProjectService.getProjectId("operate_cp","operate_cp",principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"operate_cp","master");
        assertTrue(operateOnCodeProject.canScanCodeProject(codeProject));
    }
}