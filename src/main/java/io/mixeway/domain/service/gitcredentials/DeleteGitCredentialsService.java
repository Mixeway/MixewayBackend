package io.mixeway.domain.service.gitcredentials;

import io.mixeway.db.entity.GitCredentials;
import io.mixeway.db.repository.GitCredentialsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class DeleteGitCredentialsService {
    private final GitCredentialsRepository gitCredentialsRepository;

    public void remove(GitCredentials gitCredentials) {
        gitCredentialsRepository.delete(gitCredentials);
    }
}
