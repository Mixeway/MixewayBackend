package io.mixeway.domain.service.infrascan;

import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.InfraScanRepository;
import io.mixeway.db.repository.NessusScanTemplateRepository;
import io.mixeway.domain.service.nessusscantemplate.FindNessusScanTemplateService;
import io.mixeway.scanmanager.service.network.NetworkScanClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class GetOrCreateInfraScanService {
    private final InfraScanRepository infraScanRepository;
    private final FindNessusScanTemplateService findNessusScanTemplateService;


    public InfraScan create(Map.Entry<NetworkScanClient, Set<Interface>> keyValue, String requestUIDD, Project project, boolean auto){
        Scanner scanner = keyValue.getKey().getScannerFromClient(
                Objects.requireNonNull(keyValue.getValue().stream().findFirst().orElse(null)).getRoutingDomain());
        if (scanner == null){
            throw new NullPointerException("There is no scanner in given domain ");
        }
        InfraScan scan = new InfraScan();

        scan.setInterfaces(keyValue.getValue());
        scan.setRequestId(requestUIDD);
        scan.setScanFrequency(1);
        scan.setScheduled(false);
        scan.setRunning(false);
        scan.setInQueue(true);
        scan.setIsAutomatic(auto);
        scan.setNessus(scanner);
        scan.setNessusScanTemplate(findNessusScanTemplateService.findTemplateFor(scanner));
        scan.setProject(project);
        scan.setPublicip(false);

        return infraScanRepository.saveAndFlush(scan);
    }
    public InfraScan create(Scanner scanner, Project project, boolean auto, Set<Interface> intfs, boolean scheduled) {
        InfraScan scan = new InfraScan();
        scan = new InfraScan();
        scan.setIsAutomatic(auto);
        scan.setNessus(scanner);
        scan.setNessusScanTemplate(findNessusScanTemplateService.findTemplateFor(scanner));
        scan.setProject(project);
        scan.setPublicip(false);
        scan.setRunning(false);
        scan.setInterfaces(intfs);
        scan.setScanFrequency(1);
        scan.setScheduled(scheduled);
        return infraScanRepository.saveAndFlush(scan);
    }
}
