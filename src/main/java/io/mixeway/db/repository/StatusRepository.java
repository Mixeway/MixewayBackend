package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import io.mixeway.db.entity.Status;

public interface StatusRepository extends JpaRepository<Status, Long> {
    Status findByName(String name);
}
