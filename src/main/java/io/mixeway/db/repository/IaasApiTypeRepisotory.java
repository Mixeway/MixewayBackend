package io.mixeway.db.repository;

import io.mixeway.db.entity.IaasApiType;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author gsiewruk
 */
public interface IaasApiTypeRepisotory extends JpaRepository<IaasApiType,Long> {
    IaasApiType findByName(String name);
}
