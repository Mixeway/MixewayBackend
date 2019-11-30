package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import io.mixeway.db.entity.Journal;

@Repository
public interface JournalRepository extends JpaRepository<Journal,Long> {
}
