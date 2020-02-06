package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.ScannerType;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ScannerTypeRepository extends JpaRepository<ScannerType, Long>{
	
    ScannerType findByNameIgnoreCase(String name);

    @Query("Select st from ScannerType st where st.name in ('Checkmarx','Fortify SSC')")
    List<ScannerType> getCodeScanners();
}
