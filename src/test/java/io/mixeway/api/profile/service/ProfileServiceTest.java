package io.mixeway.api.profile.service;

import io.mixeway.api.profile.model.UpdateProfileModel;
import io.mixeway.api.profile.model.UserProfile;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.Principal;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ProfileServiceTest {
    private final ProfileService profileService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;

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
        Mockito.when(principal.getName()).thenReturn("profile_service");
        User userToCreate = new User();
        userToCreate.setUsername("profile_service");
        userToCreate.setCommonName("profile_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        Project project = getOrCreateProjectService.getProjectId("profile_service", "profile_service", principal);
    }

    @Test
    void showProjects() {
        Mockito.when(principal.getName()).thenReturn("profile_service");
        ResponseEntity<UserProfile> userProfileResponseEntity = profileService.showProjects(principal);
        assertEquals(HttpStatus.OK, userProfileResponseEntity.getStatusCode());
        assertNotNull(userProfileResponseEntity.getBody());
        assertTrue(userProfileResponseEntity.getBody().getProjects() > 0);
    }

    @Test
    void editProfile() {

        Mockito.when(principal.getName()).thenReturn("profile_service");
        UpdateProfileModel updateProfileModel = new UpdateProfileModel();
        updateProfileModel.setNewPassword("test1234");
        updateProfileModel.setNewPasswordRepeat("test1234");
        ResponseEntity<Status> statusResponseEntity = profileService.editProfile(updateProfileModel, principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    void regenerateCicdApiKey() {
        Mockito.when(principal.getName()).thenReturn("profile_service");
        ResponseEntity<Status> statusResponseEntity = profileService.regenerateCicdApiKey(principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        Optional<User> user = userRepository.findByUsername("profile_service");
        assertTrue(user.isPresent());
        assertNotNull(user.get().getApiKey());
    }
}