package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.RoutingDomain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import io.mixeway.db.entity.Asset;

@Repository
public interface AssetRepository extends JpaRepository<Asset,Long> {
	Asset findByAssetId(String assetId);
	Optional<Asset> findByProjectAndName(Project project, String name);
	List<Asset> findByProjectId(Long id);
	List<Asset> findByProject(Project project);
	List<Asset> findByProjectIdAndOrigin(Long id, String origin);
	List<Asset> findByProjectAndActive(Project project, Boolean active);
	List<Asset> findByProjectAndRoutingDomain(Project project, RoutingDomain routingDomain);
	Long countByProject(Project project);
	Optional<Asset> findByName(String name);
	List<Asset> findByActive(Boolean active);
	@Query(value="SELECT distinct(asset_id) from asset_softwarepacket", nativeQuery = true)
	List<Integer> getAssetIdWithPackets();
	@Modifying
	@Query(value="delete from asset a where not exists (select 1 from interface i where i.asset_id = a.id)", nativeQuery=true)
	void deleteAsset();

	@Query(value="select distinct a from Asset a, Interface i where i.scanRunning=true and i.asset=a")
	List<Asset> getAssetsWithRunningInterfaces();

	List<Asset> findByInterfacesIsNull();

	@Modifying
	@Query(value="delete from asset_securitygroup where asset_id in (select a.id from asset a where not exists (select 1 from interface i where i.asset_id = a.id))",nativeQuery=true)
	void delteSecurityGroupMapping();
	@Modifying
	@Query(value="delete from asset_softwarepacket where asset_id in (select a.id from asset a where not exists (select 1 from interface i where i.asset_id = a.id))",nativeQuery=true)
	void delteSoftwarePacketMapping();
	@Modifying
	@Query(value="delete from software where asset_id in (select a.id from asset a where not exists (select 1 from interface i where i.asset_id = a.id))",nativeQuery=true)
	void delteSoftwareMapping();
	Optional<Asset> findByNameAndProject(String name, Project project);
    @Modifying
	@Query(value="update asset set active = false where routingdomain_id =?1", nativeQuery =true )
	void disactivateAssetByRoutingDomain(Long routingdomain_id);
	List<Asset> findByRequestId(String requestId);
	@Query(value="select * from asset where project_id=?1",nativeQuery=true)
	List<Asset> getAssetForProjectByNativeQuery(Long project_id);
	@Modifying
	@Query(value = "update Asset a set a.active=:status where a.project=:project")
    void updateStatusOfAssetByProject(@Param("project") Project project,@Param("status") boolean status);

	@Query(value= "select a from Asset a, Interface i where a.project.id=?1 and i.asset=a and i.privateip=?2")
	Optional<Asset> findAssetByProjectAndPrivateIp(Long projectid, String privateip);
}
