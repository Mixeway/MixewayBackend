package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.Proxies;

import java.util.Optional;

public interface ProxiesRepository extends JpaRepository<Proxies, Long> {

    Optional<Proxies> findByIpAndPort(String ip, String port);
}
