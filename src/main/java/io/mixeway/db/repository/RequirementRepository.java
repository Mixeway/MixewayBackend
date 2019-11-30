package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.Requirement;

public interface RequirementRepository extends JpaRepository<Requirement, Long> {
	
	Requirement findByCode(String code);

}
