package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import io.mixeway.db.entity.SecurityGroupRule;

@Repository
public interface SecurityGroupRuleRepository extends JpaRepository<SecurityGroupRule, Long> {
	
	SecurityGroupRule findByRuleid(String ruleid);

}
