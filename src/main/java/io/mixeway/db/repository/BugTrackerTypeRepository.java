package io.mixeway.db.repository;

import io.mixeway.db.entity.BugTrackerType;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BugTrackerTypeRepository extends JpaRepository <BugTrackerType, Long> {
    BugTrackerType findByName(String name);
}
