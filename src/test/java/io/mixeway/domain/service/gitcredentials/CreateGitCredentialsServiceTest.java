package io.mixeway.domain.service.gitcredentials;

import io.mixeway.db.entity.GitCredentials;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class CreateGitCredentialsServiceTest {
    private final CreateGitCredentialsService createGitCredentialsService;

    @Test
    void create() {
        GitCredentials gitCredentials = new GitCredentials();
        gitCredentials.setUrl("https://createcreds");
        GitCredentials gitCredentials1 = createGitCredentialsService.create(gitCredentials);
        assertNotNull(gitCredentials1);
        assertTrue(gitCredentials1.getId() > 0);
    }
}