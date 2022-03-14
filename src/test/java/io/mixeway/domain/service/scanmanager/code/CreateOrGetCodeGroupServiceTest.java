package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.CreateProjectService;
import io.mixeway.domain.service.project.FindProjectService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class CreateOrGetCodeGroupServiceTest {
    private final CreateOrGetCodeGroupService createOrGetCodeGroupService;
    private final CreateProjectService createProjectService;
    private final UserRepository userRepository;
    private final SettingsRepository settingsRepository;
    private final FindProjectService findProjectService;
    private final CodeGroupRepository codeGroupRepository;

    @Mock
    Principal principal;

    @BeforeEach
    private void prepareDB() {
        Optional<User> user = userRepository.findByUsername("test_create_cg");
        Settings settings = settingsRepository.findAll().get(0);
        settings.setMasterApiKey("test");
        settingsRepository.save(settings);
        Mockito.when(principal.getName()).thenReturn("test_create_cg");
        if (!user.isPresent()){
            User userToCreate = new User();
            userToCreate.setUsername("test_create_cg");
            userToCreate.setPermisions("ROLE_ADMIN");
            userRepository.save(userToCreate);
            Project project = createProjectService.createAndReturnProject("test_create_cg","test_create_cg",principal);

        }
    }

    @Test
    void createOrGetCodeGroupService() {
        Optional<Project> project = findProjectService.findProjectByCiid("test_create_cg");
        assertTrue(project.isPresent());
        CodeGroup codeGroup = createOrGetCodeGroupService.createOrGetCodeGroupService(principal,"test_cg","http://repo",project.get(),"","","");
        Optional<CodeGroup> codeGroupFromRepo = codeGroupRepository.findByProjectAndName(project.get(),"test_cg");
        assertTrue(codeGroupFromRepo.isPresent());
        assertEquals(codeGroupFromRepo.get().getId(), codeGroup.getId());
    }
}