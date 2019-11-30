package io.mixeway.db.repository;

import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.WebAppScan;

public interface WebAppScanRepository extends JpaRepository<WebAppScan, Long>{

	WebAppScan findByProject(Project project);
}
