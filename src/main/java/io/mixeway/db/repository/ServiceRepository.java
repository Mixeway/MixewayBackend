package io.mixeway.db.repository;

import io.mixeway.db.entity.Interface;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import io.mixeway.db.entity.Service;

import javax.transaction.Transactional;
import java.util.List;

public interface ServiceRepository extends JpaRepository<Service,Long> {
    @Modifying
    @Transactional
    @Query(value = "update service set status_id=null where interface_id=?1",nativeQuery = true)
    void updateServiceSetStatusNullForInterface(@Param("interfaceId") Long interfaceId);

    @Modifying
    @Transactional
    @Query(value="delete from service where interface_id=?1 and status_id is null",nativeQuery = true)
    void removeOldServices(Long interfaceId);
    List<Service> findByAnInterface(@Param("interfaceId") Interface anInterface);
}
