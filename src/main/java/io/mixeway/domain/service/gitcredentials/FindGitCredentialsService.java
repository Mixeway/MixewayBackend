package io.mixeway.domain.service.gitcredentials;

import io.mixeway.db.entity.GitCredentials;
import io.mixeway.db.repository.GitCredentialsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindGitCredentialsService {
    private final GitCredentialsRepository gitCredentialsRepository;

    public List<GitCredentials> findAll(){
        return gitCredentialsRepository.findAll();
    }
    public Optional<GitCredentials> findByUrl(String url){
        return gitCredentialsRepository.findByUrl(url);
    }
    public Optional<GitCredentials> findById(Long id){
        return gitCredentialsRepository.findById(id);
    }
}
