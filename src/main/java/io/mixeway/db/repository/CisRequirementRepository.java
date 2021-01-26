package io.mixeway.db.repository;

import io.mixeway.db.entity.CisRequirement;
import io.mixeway.db.entity.Vulnerability;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
public interface CisRequirementRepository extends JpaRepository<CisRequirement, Long> {
    Optional<CisRequirement> findByName(String name);
    Optional<CisRequirement> findByNameAndType(String name, String type);
}
