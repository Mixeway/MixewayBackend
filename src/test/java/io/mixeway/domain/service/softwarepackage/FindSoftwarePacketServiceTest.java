package io.mixeway.domain.service.softwarepackage;

import io.mixeway.db.entity.SoftwarePacket;
import io.mixeway.db.repository.SoftwarePacketRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class FindSoftwarePacketServiceTest {
    private final FindSoftwarePacketService findSoftwarePacketService;
    private final SoftwarePacketRepository softwarePacketRepository;

    @Test
    void findByName() {
        SoftwarePacket softwarePacket = new SoftwarePacket();
        softwarePacket.setName("new_packet:1.1.1");
        softwarePacketRepository.save(softwarePacket);
        Optional<SoftwarePacket> softwarePacketN =  findSoftwarePacketService.findByName("test","1.0.0");
        assertFalse(softwarePacketN.isPresent());
        softwarePacketN =  findSoftwarePacketService.findByName("new_packet","1.1.1");
        assertTrue(softwarePacketN.isPresent());

    }
}