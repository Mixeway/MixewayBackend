package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import io.mixeway.db.entity.SoftwarePacket;
import org.springframework.data.repository.query.Param;

public interface SoftwarePacketRepository extends JpaRepository<SoftwarePacket, Long> {
	Optional<SoftwarePacket> findByName(String name);
	@Query( value="update softwarepacket set uptated=false",nativeQuery = true )
	List<SoftwarePacket> deactivateSoftwarePackets();
	@Query(value = "select sp.* from softwarepacket sp inner join codeproject_softwarepacket cpsp on cpsp.softwarepacket_id=sp.id where cpsp.codeproject_id in " +
			"(select id from codeproject where project_id = :projectId)",nativeQuery = true)
	List<SoftwarePacket> getSoftwarePacketForProject(@Param("projectId") Long projectId);

}
