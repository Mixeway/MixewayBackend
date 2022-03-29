package io.mixeway.domain.service.softwarepackage;

import io.mixeway.db.entity.SoftwarePacket;
import io.mixeway.db.repository.SoftwarePacketRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindSoftwarePacketService {
    private final SoftwarePacketRepository softwarePacketRepository;

    public Optional<SoftwarePacket> findByName (String name, String version){
        return softwarePacketRepository.findByName(name+":"+version);
    }

    public List<SoftwarePacket> getSoftwarePacketForProject(Long id) {
        return softwarePacketRepository.getSoftwarePacketForProject(id);
    }
}
