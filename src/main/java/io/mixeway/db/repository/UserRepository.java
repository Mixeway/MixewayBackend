package io.mixeway.db.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByCommonName(String commonName);
	Optional<User> findByUsername(String username);
	Optional<User> findByUsernameAndEnabled(String username, boolean enabled);
	Optional<User> findByUsernameOrCommonName(String username, String commonName);
	Optional<User> findByApiKey(String apiKey);
}
