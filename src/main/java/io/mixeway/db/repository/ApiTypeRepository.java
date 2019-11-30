package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.ApiType;

public interface ApiTypeRepository extends JpaRepository<ApiType, Long> {
	ApiType findByUrl(String url);

}
