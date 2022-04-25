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

    public GitCredentials updateUrl(GitCredentials credentials,GitCredentials edited){
        credentials.setUrl(edited.getUrl());
        return gitCredentialsRepository.saveAndFlush(credentials);
    }

    public GitCredentials updateUsername(GitCredentials gitCredentials, GitCredentials edited){
        gitCredentials.setUsername(edited.getUsername());
        return gitCredentialsRepository.saveAndFlush(gitCredentials);
    }
    public GitCredentials updatePassword(GitCredentials gitCredentials, GitCredentials edited){
        String repoPasswordToken = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(edited.getPassword(),repoPasswordToken)){
            gitCredentials.setPassword(repoPasswordToken);
        } else {
            gitCredentials.setPassword(edited.getPassword());
        }
        return gitCredentialsRepository.saveAndFlush(gitCredentials);
    }
}
