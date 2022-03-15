package io.mixeway.domain.service.scanner;

import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class GetScannerService {
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;

    public Optional<Scanner> getCodeScanners() {
        return scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true).stream().findFirst();
    }
}
