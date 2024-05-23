package io.mixeway.db.repository;

import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.db.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CiOperationsRepository extends JpaRepository<CiOperations,Long> {
    List<CiOperations> findByProjectOrderByInsertedDesc(Project project);
    @Query(value = "select to_char(inserted, 'YYYY-MM-DD') as date, count(*) as value from cioperations where project_id in :projectids group by date order by date desc limit 10",nativeQuery = true)
    List<OverAllVulnTrendChartData> getCiTrend(@Param("projectids") List<Long> projectIds);
    Long countByResultAndProjectIn(String result, List<Project> projects);
    List<CiOperations> findByProjectInOrderByInsertedDesc(List<Project> projects);
    Optional<CiOperations> findByCodeProjectAndCommitId(CodeProject codeProject, String commitId);
    List<CiOperations> findByProject(Project project);
    List<CiOperations> findTop20ByProjectOrderByIdDesc(Project project);

    List<CiOperations> findTop20ByCodeProjectOrderByIdDesc(CodeProject codeProject);
    List<CiOperations> findTop20ByWebappOrderByIdDesc(WebApp webApp);
    List<CiOperations> findTop20ByInterfaceObjOrderByIdDesc(Interface anInterface);

    Optional<CiOperations> findByCommitId(String commitId);
    List<CiOperations> findByCodeProject(CodeProject codeProject);
    List<CiOperations> findByWebapp(WebApp webApp);
}
