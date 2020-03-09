package io.mixeway.db.repository;

import java.util.List;
import java.util.stream.Stream;

import io.mixeway.db.entity.Interface;
import io.mixeway.pojo.BarChartProjection;
import io.mixeway.pojo.BarChartProjection2;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import io.mixeway.db.entity.InfrastructureVuln;

public interface InfrastructureVulnRepository extends JpaRepository<InfrastructureVuln, Long> {
	
	Long deleteByIntf(Interface intf);
	@Transactional
	@Modifying
	@Query(value="delete from InfrastructureVuln c where c.intf =:intf ")
	public void deleteVulnsForIntf(Interface intf);
	Long deleteByIntfIn(List<Interface> intf);
	List<InfrastructureVuln> findByIntfIn(List<Interface> intf);
	List<InfrastructureVuln> findByIntfInAndSeverityContainingIgnoreCase(List<Interface> intf, String threat);
	List<InfrastructureVuln> findByIntfInAndSeverityNot(List<Interface> intf, String threat);
	@Query(value= "select * from infrastructurevuln where interface_id in " +
			"(select id from interface where asset_id in (select id from asset where project_id =:projectId)) " +
			"and threat not in ('Log','Info')", nativeQuery = true)
	Stream<InfrastructureVuln> getVulnsForProject(@Param("projectId") Long projectId);




	List<InfrastructureVuln> findByIntfInAndSeverityNotIn(List<Interface> intf, List<String> strings);
	List<InfrastructureVuln> findByNameLikeIgnoreCaseAndIntfIn(String name, List<Interface> intf);
	List<InfrastructureVuln> findByName(String name);
	@Query("SELECT distinct i.name from InfrastructureVuln i where threat != 'Log'")
	List<String> findDistinctName();
	@Query("SELECT distinct i.name from InfrastructureVuln i where threat in ('Critical','High') and i.intf in :interfaces")
	List<String> findDistinctNameByIntfIn(@Param("interfaces") List<Interface> interfaces);
	Long countByNameAndIntfIn(String name,List<Interface> interfaces);
	Long countByName(String name);

	List<InfrastructureVuln> findBySeverityNot(String threat);
	Long countBySeverityNot(String threat);
	List<InfrastructureVuln> findByIntfInAndSeverityIn(List<Interface> intfs, List<String> threats);
	@Query(value = "SELECT i from InfrastructureVuln i where i.intf in :interfaces and i.port like '%www%'")
	List<InfrastructureVuln> getVulnsByInterfacesAndWithWWW(@Param("interfaces") List<Interface> interfaces);

	@Query(value = " select name, count(*) as value from infrastructurevuln where threat in ('Critical','Critic','High') and interface_id " +
			"in (select id from interface where asset_id in (select id from asset where project_id=?1)) group by name order by value desc limit 10", nativeQuery = true)
	List<BarChartProjection> getVulnStatisticForProjectByVulnName(@Param("projectId") Long project_id);
	@Query(value = "select a.name, count(*) as value from asset a, interface i, infrastructurevuln iv where i.id=iv.interface_id " +
			"and a.id=i.asset_id and iv.threat in ('Critical','Critic','High') and a.project_id=?1 group by a.name order by value desc limit 10", nativeQuery = true)
	List<BarChartProjection> getVulnStatisticForProjectByAssetName(@Param("projectId") Long project_id);
	@Query(value="select distinct port from infrastructurevuln where interface_id =?1 and name='Service Detection'",nativeQuery = true)
	List<String> getPortsFromInfraVulnForInterface(@Param("interfaceId")Long interfaceId);
	List<InfrastructureVuln> findByIntf(Interface intf);
	Long countByIntfInAndSeverity(List<Interface> interfaces, String threat);

	@Query(value="select count(*) as value, name as namee from infrastructurevuln where threat in ('Critical','High') group by name order by value desc limit 10", nativeQuery = true)
	List<BarChartProjection2> getTopVulns();
	@Query(value="select count(*) as value, i.privateip||' ('||a.name||')' as namee from infrastructurevuln iv, interface i, asset a where iv.interface_id=i.id and i.asset_id=a.id and iv.threat in ('Critical','High') " +
			"group by namee order by value desc limit 10",nativeQuery = true)
	List<BarChartProjection2> getTopTargets();
	@Query(value ="select count(*) from infrastructurevuln where interface_id in (select id from interface where active=true and asset_id in (select id from asset where project_id=?1))" +
			"and threat=?2", nativeQuery = true)
	Long getCountByProjectIdAndThreat(@Param("id")Long id, @Param("threat")String threat);
	@Query(value ="select count(*) from infrastructurevuln where interface_id=?1 and threat=?2", nativeQuery = true)
	Long getCountByInterfaceIdAndThreat(@Param("id")Long id, @Param("threat")String threat);
	@Query(value = "select * from infrastructurevuln where name ilike %?1%", nativeQuery = true)
	List<InfrastructureVuln> searchForName(@Param("name") String name);
	@Query(value = "select ((count(*) filter (where threat='Critical') * :critWage) + (count(*) filter (where threat='High') * :highWage) + (count(*) filter (where threat='Medium') * :mediumWage)) from " +
			"infrastructurevuln where interface_id in (select id from interface where asset_id in (select id from asset where project_id =:project_id))", nativeQuery = true)
	int countRiskForProject(@Param("project_id")Long project_id,@Param("critWage") int critWage, @Param("highWage") int highWage,@Param("mediumWage") int mediumWage);
	@Query(value = "select ((count(*) filter (where threat='Critical') * :critWage) + (count(*) filter (where threat='High') * :highWage) + (count(*) filter (where threat='Medium') * :mediumWage)) from " +
			"infrastructurevuln where interface_id =:interface_id", nativeQuery = true)
	int countRiskForInterface(@Param("interface_id")Long interface_id,@Param("critWage") int critWage, @Param("highWage") int highWage,@Param("mediumWage") int mediumWage);

}
