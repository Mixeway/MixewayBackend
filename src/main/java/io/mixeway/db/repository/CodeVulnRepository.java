package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import io.mixeway.pojo.BarChartProjection;
import io.mixeway.pojo.BarChartProjection2;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import org.springframework.data.repository.query.Param;
import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeVuln;

public interface CodeVulnRepository extends JpaRepository<CodeVuln, Long>{
	Optional<CodeVuln> findById(Long id);
	public Long deleteByCodeGroup(CodeGroup codeGroup);
	public Long deleteByCodeProject(CodeProject codeProject);
	public List<CodeVuln> findByCodeProjectAndSeverityAndAnalysis(CodeProject codeProject, String severity, String analysis);
	public List<CodeVuln> findByCodeProjectInAndSeverityContainingIgnoreCaseAndAnalysis(List<CodeProject> list, String severity, String analysis);
	@Query("SELECT distinct c.name from CodeVuln c where severity != 'Log'")
	public List<String> findDistinctName();
	@Query(value = "SELECT * from codevuln where id=?1", nativeQuery = true)
	public Optional<CodeVuln> getVulnsById(@Param("id") Long id);
	@Query("SELECT distinct c.name from CodeVuln c where analysis != 'Not an Issue' and analysis!='Reliability Issue'")
	public List<String> findDistinctNameNotNotAnIssue();
	@Modifying
	@Query(value="delete from CodeVuln c where c.codeProject =:codeProject ")
	public void deleteVulnsForCodeProject(CodeProject codeProject);
	@Modifying
	@Query(value="delete from CodeVuln c where c.codeGroup =:codeGroup ")
	public void deleteVulnsForCodeGroup(CodeGroup codeGroup);
	List<CodeVuln> findByCodeProject(CodeProject codeProject);
	 Long countByName(String name);
	 List<CodeVuln> findByName(String name);
	Stream<CodeVuln> findByCodeGroupIn(Set<CodeGroup> groups);
	@Query(value="select cv from CodeVuln cv")
	Stream<CodeVuln> findAllCodeVulns();
	Stream<CodeVuln> findByCodeGroupInAndAnalysisNot(Set<CodeGroup> groups, String analysis);
	List<CodeVuln> findByCodeProjectInAndAnalysisNot(List<CodeProject> project, String analysis);
	List<CodeVuln> findByCodeGroupInAndSeverityIn(Set<CodeGroup> groups, List<String> severities);
	List<CodeVuln> findByCodeGroupInAndSeverityInAndAnalysis(Set<CodeGroup> groups, List<String> severities, String analysis);
	List<CodeVuln> findByCodeProjectAndAnalysisNot(CodeProject codeProject, String analysis);
	List<CodeVuln> findByCodeGroupAndAnalysisNot(CodeGroup codeGroup, String analysis);
	@Query(value = " select cv.name as name, count(*) as value from codeproject cp, codegroup cg, codevuln cv where cv.codeproject_id=cp.id " +
			"and cp.codegroup_id= cg.id and cg.project_id=?1 and cv.analysis!='Not an Issue' group by cv.name order by value desc limit 10",nativeQuery = true)
	List<BarChartProjection> getCodeVulnStatisticByVulnName(@Param("projectId") Long projectId);

	@Query(value = "select cp.name as name, count(*) as value from codeproject cp, codegroup cg, codevuln cv where cv.codeproject_id=cp.id " +
			"and cp.codegroup_id= cg.id and cg.project_id=?1 and cv.analysis!='Not an Issue' group by cp.name order by value desc limit 10",nativeQuery = true)
	List<BarChartProjection> getCodeVulnStatisticByCodeProjectName(@Param("projectId") Long projectId);
	Long countByCodeProjectInAndSeverityAndAnalysis(List<CodeProject> codeProjects, String severity, String analysis);

	@Query(value="select count(*) as value, name as namee from codevuln where severity in ('Critical','High') and analysis != 'Not an Issue' group by name order by value desc limit 10", nativeQuery = true)
	List<BarChartProjection2> get10TenCodeVulns();
	@Query(value="select count(*) as value, cp.name as namee from codevuln cv, codeproject cp where cp.id=cv.codeproject_id and cv.severity in ('Critical','High') and cv.analysis != 'Not an Issue' group by cp.name order by value desc limit 10;", nativeQuery = true)
	List<BarChartProjection2> get10TopCodeProjects();

	@Query(value="select count(*) from codevuln where codegroup_id in (select id from codegroup where project_id=?1) and severity=?2 and analysis=?3", nativeQuery = true)
    Long getCountByProjectIdSeverityAndAnalysis(@Param("id") Long id, @Param("severity") String severity, @Param("analysis") String analysis);

    @Query(value="select count(*) from codevuln where codeproject_id=?1 and severity=?2 and analysis=?3", nativeQuery = true)
    Long getCountByCodeProjectIdSeverityAndAnalysis(@Param("id") Long id, @Param("severity") String severity, @Param("analysis") String analysis);
	@Query(value = "select * from codevuln where name ilike %?1%", nativeQuery = true)
	List<CodeVuln> searchForName(@Param("name") String name);
	List<CodeVuln> findByCodeGroup(CodeGroup codeGroup);
	@Query(value = "select ((count(*) filter (where severity='Critical') * :critWage) + (count(*) filter (where severity='High') * :highWage)) from " +
			"codevuln where codegroup_id in (select id from codegroup where project_id=:project_id) and analysis =:analysis", nativeQuery = true)
	int countRiskForProject(@Param("project_id")Long project_id,@Param("critWage") int critWage, @Param("highWage") int highWage,
							@Param("analysis") String analysis);
	@Query(value = "select ((count(*) filter (where severity='Critical') * :critWage) + (count(*) filter (where severity='High') * :highWage)) from " +
			"codevuln where codeproject_id =:codeProject_id and analysis =:analysis", nativeQuery = true)
	int countRiskForCodeProject(@Param("codeProject_id")Long codeProject_id,@Param("critWage") int critWage, @Param("highWage") int highWage,
							@Param("analysis") String analysis);

}
