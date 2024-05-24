package io.mixeway.db.repository;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Metric;
import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MetricRepository extends JpaRepository<Metric, Long> {
    Optional<Metric> findByProjectIsNull();
    Optional<Metric> findByProject(Project project);
}
