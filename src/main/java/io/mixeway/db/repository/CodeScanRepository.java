package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import io.mixeway.db.entity.CodeScan;

public interface CodeScanRepository extends JpaRepository<CodeScan,Long> {
}
