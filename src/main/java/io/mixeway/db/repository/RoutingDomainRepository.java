package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.RoutingDomain;

public interface RoutingDomainRepository extends JpaRepository<RoutingDomain, Long>{
	
	RoutingDomain findByName(String name);

}
