package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import io.mixeway.db.entity.Asset;

@Repository
public interface AssetRepository extends JpaRepository<Asset,Long> {
	Asset findByAssetId(String assetId);
	List<Asset> findByProjectId(Long id);
	List<Asset> findByProject(Project project);
	List<Asset> findByProjectIdAndOrigin(Long id, String origin);
	List<Asset> findByProjectAndActive(Project project, Boolean active);
	Long countByProject(Project project);
	Optional<Asset> findByName(String name);
	List<Asset> findByActive(Boolean active);
	@Query(value="SELECT distinct(asset_id) from asset_softwarepacket", nativeQuery = true)
	List<Integer> getAssetIdWithPackets();
	@Modifying
	@Query(value="delete from asset a where not exists (select 1 from interface i where i.asset_id = a.id)", nativeQuery=true)
	void deleteAsset();
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

}