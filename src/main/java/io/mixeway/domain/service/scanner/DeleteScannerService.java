package io.mixeway.domain.service.scanner;

import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.ScannerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class DeleteScannerService {
    private final ScannerRepository scannerRepository;

    public boolean removeScanner(Long id){
        Optional<Scanner> scanner = scannerRepository.findById(id);
        if (scanner.isPresent()){
            scannerRepository.deleteById(id);
            return true;
        } else {
            return false;
        }
    }
}
