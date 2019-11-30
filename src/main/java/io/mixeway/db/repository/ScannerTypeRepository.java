package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.ScannerType;

public interface ScannerTypeRepository extends JpaRepository<ScannerType, Long>{
	
	public ScannerType findByNameIgnoreCase(String name);
}
