/*
 * @created  2020-10-14 : 23:18
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.db.repository;

import io.mixeway.db.entity.GitCredentials;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GitCredentialsRepository extends JpaRepository<GitCredentials, Long> {
    Optional<GitCredentials> findByUrl(String url);
}
