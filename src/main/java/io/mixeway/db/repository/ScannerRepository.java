package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.db.entity.Scanner;
import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.db.entity.RoutingDomain;

public interface ScannerRepository extends JpaRepository<Scanner, Long> {
	
	List<Scanner> findByUsePublic(Boolean usePublic);
	List<Scanner> findByStatus(Boolean status);
	Optional<Scanner> findByApiUrlAndScannerType(String url, ScannerType scannerType);
	List<Scanner> findByScannerType(ScannerType scannerType);
	List<Scanner> findByScannerTypeAndStatus(ScannerType scannerType, Boolean status);
	List<Scanner> findByRoutingDomainAndScannerTypeIn(RoutingDomain routingDomain, List<ScannerType> scannerTypes);
	List<Scanner> findByRoutingDomainAndStatusAndScannerTypeIn(RoutingDomain routingDomain, Boolean status, List<ScannerType> scannerTypes);
	@Query(value = "select * from nessus where id=?1",nativeQuery = true)
	Optional<Scanner> getScannerById(@Param("id") Long id);
	@Query("select distinct s.scannerType from Scanner s where s.status=true")
	List<ScannerType> getDistinctScannerTypes();
	List<Scanner> findByScannerTypeAndRoutingDomain(ScannerType scannerType, RoutingDomain routingDomain);
    List<Scanner> findByScannerTypeInAndStatus(List<ScannerType> scannerTypes, Boolean status);
    Scanner findByScannerTypeInAndRoutingDomain(List<ScannerType> scannerTypes, RoutingDomain routingDomain);
    Scanner findTopByScannerTypeInAndRoutingDomain(List<ScannerType> scannerTypes, RoutingDomain routingDomain);
    @Query("select distinct routingDomain from Scanner")
	List<RoutingDomain> getDistinctByRoutingDomain();
}
