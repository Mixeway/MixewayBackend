package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import io.mixeway.db.entity.SecurityGroup;

@Repository
public interface SecurityGroupRepository extends JpaRepository<SecurityGroup, Long>{
	
	SecurityGroup findBySecuritygroupid(String securitygroupid);

}
