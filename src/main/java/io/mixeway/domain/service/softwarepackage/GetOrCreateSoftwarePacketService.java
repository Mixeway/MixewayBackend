package io.mixeway.domain.service.softwarepackage;

import io.mixeway.db.entity.SoftwarePacket;
import io.mixeway.db.repository.SoftwarePacketRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class GetOrCreateSoftwarePacketService {
    private final FindSoftwarePacketService findSoftwarePacketService;
    private final SoftwarePacketRepository softwarePacketRepository;

    public SoftwarePacket getOrCreateSoftwarePacket(String name, String version){
        Optional<SoftwarePacket> softwarePacket = findSoftwarePacketService.findByName(name,version);
        return softwarePacket.orElseGet(() -> create(name, version));
    }

    public SoftwarePacket create(String name, String version){
        SoftwarePacket softwarePacket = new SoftwarePacket();
        softwarePacket.setName(name+":"+version);
        return softwarePacketRepository.saveAndFlush(softwarePacket);
    }
}
