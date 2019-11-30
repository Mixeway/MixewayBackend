package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import io.mixeway.db.entity.FortifySingleApp;

import java.util.List;
import java.util.Optional;

public interface FortifySingleAppRepository extends JpaRepository<FortifySingleApp,Long> {
    List<FortifySingleApp> findByFinished(Boolean finished);
    List<FortifySingleApp> findByFinishedAndDownloaded(Boolean finished, Boolean downloaded);
    Optional<FortifySingleApp> findByRequestId(String requestId);
}
