package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.LoginSequence;

public interface LoginSequenceRepository extends JpaRepository<LoginSequence, Long> {

}
