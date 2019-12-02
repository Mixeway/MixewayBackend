package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import io.mixeway.db.entity.Interface;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.RoutingDomain;

@Repository
public interface InterfaceRepository extends JpaRepository<Interface, Long>{
	Interface findByMacaddr(String macaddr);
	List<Interface> findByAsset(Asset asset);
	Long countByFloatingipNotNull();
	List<Interface> findByAssetInAndFloatingipNotNull(List<Asset> assets);
	List<Interface> findByAssetIn(List<Asset> assets);
	List<Interface> findByAssetInAndRoutingDomain(List<Asset> assets, RoutingDomain routingDomain);
	List<Interface> findByFloatingipAndActiveAndAssetIn(String privateip, Boolean active ,List<Asset> assets);
	List<Interface> findByPrivateipAndActiveAndAssetIn(String privateip, Boolean active ,List<Asset> assets);
	Optional<Interface> findByAssetAndPrivateip(Asset asset, String privateip);
	@Query( "select i from Interface i where privateip=:ip and active=:active and asset in :assets" )
	List<Interface> getActiveInterfacePrivate(@Param("ip")String privateip, @Param("active")Boolean active, @Param("assets")List<Asset> assets);
	@Query( "select i from Interface i where privateip=:ip" )
	List<Interface> getInterfacePrivate(@Param("ip")String privateip);


	@Query("select i from Interface i where asset in :assets and hostid != 0")
	List<Interface> getInterfaceForAssetsWithHostIdSet(@Param("assets")List<Asset> assets);

	@Query(value="select i from Interface i where i.asset in :assets and (i.privateip=:ip or i.floatingip=:ip)")
	List<Interface> getInterfaceForIPandAssets(@Param("ip")String ip, @Param("assets")List<Asset> assets);
	Long deleteByAssetIn(List<Asset> assets);
	Long deleteByAsset(Asset asset);
	@Modifying
	@Query(value="delete from interface i where not exists (select 1 from infrastructurevuln iv where iv.interface_id = i.id)", nativeQuery=true)
	void deleteInterface();
	Set<Interface> findByAssetInAndRoutingDomainAndActive(Set<Asset> assets, RoutingDomain routingDomain, Boolean active);
	Optional<Interface> findByAssetInAndPrivateip(Set<Asset> assets, String privateip);
	Optional<Interface> findByAssetInAndPrivateipAndActive(Set<Asset> assets, String privateip, Boolean active);
	@Query(value = "select * from interface where privateip ilike %?1% limit 100", nativeQuery = true)
	List<Interface> searchForIp(@Param("ip") String ip);

}