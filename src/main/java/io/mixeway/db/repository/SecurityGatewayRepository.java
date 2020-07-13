package io.mixeway.db.repository;

import io.mixeway.db.entity.SecurityGateway;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author gsiewruk
 */
public interface SecurityGatewayRepository extends JpaRepository<SecurityGateway, Long> {
}
