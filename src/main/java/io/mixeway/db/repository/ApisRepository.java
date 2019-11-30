package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.Apis;

public interface ApisRepository extends JpaRepository<Apis, String>{
	
	public Apis findByName(String name);

}
