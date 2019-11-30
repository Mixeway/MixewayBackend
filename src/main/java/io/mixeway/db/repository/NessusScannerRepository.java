package io.mixeway.db.repository;

import java.util.List;

import io.mixeway.db.entity.Scanner;
import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.NessusScanner;

public interface NessusScannerRepository extends JpaRepository<NessusScanner, Long> {
	List<NessusScanner> findByNessus(Scanner nessus);

}
