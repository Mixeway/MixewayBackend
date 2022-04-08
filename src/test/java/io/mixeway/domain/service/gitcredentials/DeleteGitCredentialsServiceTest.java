package io.mixeway.domain.service.gitcredentials;

import io.mixeway.db.entity.GitCredentials;
import io.mixeway.db.repository.GitCredentialsRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class DeleteGitCredentialsServiceTest {
    private final DeleteGitCredentialsService deleteGitCredentialsService;
    private final CreateGitCredentialsService createGitCredentialsService;
    private final GitCredentialsRepository gitCredentialsRepository;

    @Test
    void remove() {
        GitCredentials gitCredentials = new GitCredentials();
        gitCredentials.setUrl("https://removed");
        gitCredentials = createGitCredentialsService.create(gitCredentials);
        deleteGitCredentialsService.remove(gitCredentials);
        Optional<GitCredentials> gitCredentials1 = gitCredentialsRepository.findByUrl("https://removed");
        assertFalse(gitCredentials1.isPresent());
    }
}