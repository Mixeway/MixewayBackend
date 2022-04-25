package io.mixeway.domain.service.scannertype;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.ScannerType;
import io.mixeway.db.repository.ScannerTypeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindScannerTypeService {
    private final ScannerTypeRepository scannerTypeRepository;

    public List<ScannerType> findInfraScannerTypes(){
        return Arrays.asList(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS),
                scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NESSUS), scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_NEXPOSE));
    }

    public List<ScannerType> findAll() {
        return scannerTypeRepository.findAll();
    }

    public ScannerType findByName(String name) {
        return scannerTypeRepository.findByNameIgnoreCase(name);
    }

    public ScannerType findByNameIgnoreCase(String name) {
        return scannerTypeRepository.findByNameIgnoreCase(name);
    }
}
