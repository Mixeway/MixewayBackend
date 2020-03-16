package io.mixeway.db.repository;

import io.mixeway.db.entity.Project;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import io.mixeway.db.entity.CiOperations;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CiOperationsRepository extends JpaRepository<CiOperations,Long> {
    List<CiOperations> findByProjectOrderByInsertedDesc(Project project);
    @Query(value = "select to_char(inserted, 'YYYY-MM-DD') as date, count(*) as value from cioperations where project_id in :projectids group by date order by date desc limit 10",nativeQuery = true)
    List<OverAllVulnTrendChartData> getCiTrend(@Param("projectids") List<Long> projectIds);
    Long countByResultAndProjectIn(String result, List<Project> projects);
    List<CiOperations> findByProjectInOrderByInsertedDesc(List<Project> projects);
}
