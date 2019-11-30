package io.mixeway.db.repository;

import io.mixeway.db.entity.Scanner;
import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.NessusScanTemplate;

public interface NessusScanTemplateRepository extends JpaRepository<NessusScanTemplate, Long> {

	NessusScanTemplate findByNameAndNessus(String name, Scanner nessus);
}
