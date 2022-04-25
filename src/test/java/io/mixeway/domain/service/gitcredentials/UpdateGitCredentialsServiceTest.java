package io.mixeway.domain.service.gitcredentials;

import io.mixeway.db.entity.GitCredentials;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
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
class UpdateGitCredentialsServiceTest {
    private final UpdateGitCredentialsService updateGitCredentialsService;
    private final CreateGitCredentialsService createGitCredentialsService;
    private final UserRepository userRepository;

    @Mock
    Principal principal;
    @BeforeAll
    private void setUpTest(){
        Mockito.when(principal.getName()).thenReturn("update_gitcreds");
        User user = new User();
        user.setUsername("update_gitcreds");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
    }

    @Test
    void updateUrl() {
        GitCredentials gitCredentials = new GitCredentials();
        gitCredentials.setUrl("https://url");
        gitCredentials = createGitCredentialsService.create(gitCredentials);
        GitCredentials edited = gitCredentials;
        edited.setUrl("https://new.url");
        gitCredentials = updateGitCredentialsService.updateUrl(gitCredentials, edited);
        assertEquals("https://new.url", gitCredentials.getUrl());

    }

    @Test
    void updateUsername() {
        GitCredentials gitCredentials = new GitCredentials();
        gitCredentials.setUsername("username");
        gitCredentials = createGitCredentialsService.create(gitCredentials);
        GitCredentials edited = gitCredentials;
        edited.setUsername("new_username");
        gitCredentials = updateGitCredentialsService.updateUsername(gitCredentials, edited);
        assertEquals("new_username", gitCredentials.getUsername());
    }

    @Test
    void updatePassword() {
        GitCredentials gitCredentials = new GitCredentials();
        gitCredentials.setPassword("password");
        gitCredentials = createGitCredentialsService.create(gitCredentials);
        GitCredentials edited = gitCredentials;
        edited.setPassword("new_password");
        gitCredentials = updateGitCredentialsService.updatePassword(gitCredentials, edited);
        assertEquals("new_password", gitCredentials.getPassword());

    }
}