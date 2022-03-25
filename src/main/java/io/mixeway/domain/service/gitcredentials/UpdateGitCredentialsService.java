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
public class UpdateGitCredentialsService {
    private final GitCredentialsRepository gitCredentialsRepository;
    private final VaultHelper vaultHelper;

    public void updateUrl(GitCredentials credentials,GitCredentials edited){
        credentials.setUrl(edited.getUrl());
        gitCredentialsRepository.save(credentials);
    }

    public void updateUsername(GitCredentials gitCredentials, GitCredentials edited){
        gitCredentials.setUsername(edited.getUsername());
        gitCredentialsRepository.save(gitCredentials);
    }
    public void updatePassword(GitCredentials gitCredentials, GitCredentials edited){
        String repoPasswordToken = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(edited.getPassword(),repoPasswordToken)){
            gitCredentials.setPassword(repoPasswordToken);
        } else {
            gitCredentials.setPassword(edited.getPassword());
        }
        gitCredentialsRepository.save(gitCredentials);
    }
}
