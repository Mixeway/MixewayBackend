package io.mixeway.db.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Software;

public interface SoftwareRepository extends JpaRepository<Software, Long> {
	Optional<Software> findByAssetAndName(Asset asset, String name);

}
