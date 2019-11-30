package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import io.mixeway.db.entity.SoftwarePacket;

public interface SoftwarePacketRepository extends JpaRepository<SoftwarePacket, Long> {
	Optional<SoftwarePacket> findByName(String name);
	@Query( value="update softwarepacket set uptated=false",nativeQuery = true )
	List<SoftwarePacket> deactivateSoftwarePackets();        

}
