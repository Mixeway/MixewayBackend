package io.mixeway.domain.service.gitcredentials;

import io.mixeway.db.entity.GitCredentials;
import io.mixeway.db.repository.GitCredentialsRepository;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class CreateGitCredentialsService {
    private final GitCredentialsRepository gitCredentialsRepository;
    private final VaultHelper vaultHelper;

    public GitCredentials create(GitCredentials gitCredentials){
        String repoPasswordToken = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(gitCredentials.getPassword(),repoPasswordToken)){
            gitCredentials.setPassword(repoPasswordToken);
        }
        return gitCredentialsRepository.saveAndFlush(gitCredentials);
    }
}
