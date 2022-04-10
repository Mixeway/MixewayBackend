package io.mixeway.domain.service.gitcredentials;

import io.mixeway.db.entity.GitCredentials;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FindGitCredentialsServiceTest {
    private final FindGitCredentialsService findGitCredentialsService;
    private final CreateGitCredentialsService createGitCredentialsService;
    @Test
    void findAll() {
        GitCredentials gitCredentials = new GitCredentials();
        gitCredentials.setUrl("https://createcreds1");
        GitCredentials gitCredentials1 = createGitCredentialsService.create(gitCredentials);
        assertNotNull(gitCredentials1);
        assertTrue(gitCredentials1.getId() > 0);
        assertTrue(findGitCredentialsService.findAll().size() > 0);

    }

    @Test
    void findByUrl() {
        GitCredentials gitCredentials = new GitCredentials();
        gitCredentials.setUrl("https://createcreds2");
        GitCredentials gitCredentials1 = createGitCredentialsService.create(gitCredentials);
        assertNotNull(gitCredentials1);
        assertTrue(findGitCredentialsService.findByUrl("https://createcreds2").isPresent());
    }

    @Test
    void findById() {
        GitCredentials gitCredentials = new GitCredentials();
        gitCredentials.setUrl("https://createcreds3");
        GitCredentials gitCredentials1 = createGitCredentialsService.create(gitCredentials);
        assertNotNull(gitCredentials1);
        Optional<GitCredentials> gitCredentials2 = findGitCredentialsService.findById(gitCredentials1.getId());
        assertTrue(gitCredentials2.isPresent());
    }
}