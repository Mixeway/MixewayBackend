package io.mixeway.db.repository;

import java.util.List;
import java.util.Set;

import io.mixeway.db.projection.BarChartProjection;
import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.jpa.repository.Query;
import io.mixeway.db.entity.ApiType;
import io.mixeway.db.entity.Node;
import io.mixeway.db.entity.NodeAudit;
import io.mixeway.db.entity.Requirement;

public interface NodeAuditRepository extends JpaRepository<NodeAudit, Long> {
	NodeAudit findByRequirementAndNodeAndType(Requirement requirement, Node node, ApiType apiType);
	List<NodeAudit> findByScore(String score);
	List<NodeAudit> findByNodeIn(Set<Node> nodes);
	List<NodeAudit> findByNodeInAndScore(Set<Node> nodes, String score);
	List<NodeAudit> findByNodeInAndScoreIn(Set<Node> nodes, List<String> score);

	@Query(value = "select n.name, count(*) as value from node n, nodeaudit na where na.node_id =n.id " +
			"and n.project_id=?1 and na.score in ('WARN','FAIL') group by n.name order by value desc limit 10",nativeQuery = true)
	List<BarChartProjection> getVulnsByNodeName(Long projectId);
	@Query(value="select r.name, count(*) as value from requirement r, nodeaudit na, node n where na.node_id =n.id " +
			"and n.project_id=?1 and na.score in ('WARN','FAIL') and na.requirement_id=r.id group by r.name order by value desc limit 10",nativeQuery = true)
	List<BarChartProjection> getVulnsByRequirements(Long projectId);
}
