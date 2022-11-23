package io.mixeway.domain.service.scanner;

import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindScannerService {
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;

    public List<Scanner> findAllScanners(){
        return scannerRepository.findAll();
    }

    public Scanner getById(long id){
        return scannerRepository.getOne(id);
    }

    public Optional<Scanner> findById(long id){
        return scannerRepository.findById(id);
    }

    public List<RoutingDomain> getDistinctByRoutingDomain() {
        return scannerRepository.getDistinctByRoutingDomain();
    }

    public List<ScannerType> getDistinctScannerTypes() {
       return scannerRepository.getDistinctScannerTypes();
    }

    public List<Scanner> findByScannerType(String scannerTypeAcunetix) {
        ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(scannerTypeAcunetix);
        return scannerRepository.findByScannerType(scannerType);
    }
}
