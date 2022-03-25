package io.mixeway.domain.service.infrascan;

import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.InfraScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindInfraScanService {
    private final InfraScanRepository infraScanRepository;

    public List<InfraScan> findByProjectAndRunning(Project project){
        return infraScanRepository.findByProjectAndIsAutomatic(project,false).stream().filter(InfraScan::getRunning).collect(Collectors.toList());
    }

    public boolean canConfigureAutomaticScan(Project project, Scanner scanner){
        return infraScanRepository.findByIsAutomaticAndProjectAndNessus(true,project,scanner).size() == 0;
    }

    public List<InfraScan> getRunning5Scans(){
        return infraScanRepository.getRandom5RunningScans();
    }

    public boolean hasProjectNoInfraScanRunning(Project project){
        return infraScanRepository.findByProjectAndRunning(project,true).size() == 0;
    }

    public List<InfraScan> findRunning(Scanner scanner){
        return infraScanRepository.findByNessusAndRunning(scanner, true);
    }
    public List<InfraScan> findInQueue(Scanner scanner){
        return infraScanRepository.findByNessusAndInQueue(scanner, true);
    }
}