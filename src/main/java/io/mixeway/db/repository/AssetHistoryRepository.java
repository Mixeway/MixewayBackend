package io.mixeway.db.repository;

import io.mixeway.db.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface AssetHistoryRepository extends JpaRepository<AssetHistory, Long> {
    List<AssetHistory> findByWebapp(WebApp webApp);
    List<AssetHistory> findByCodeProject(CodeProject codeProject);
    List<AssetHistory> findByInterfaceObj(Interface anInterface);


    @Query(value="select * from assethistory v where v.codeproject_id= ?1 order by v.inserted desc limit ?2", nativeQuery = true)
    List<AssetHistory> getCodeProjectHistory(Long project, int limit);

    @Query(value="select * from assethistory v where v.webapp_id= ?1 order by v.inserted desc limit ?2", nativeQuery = true)
    List<AssetHistory> getWebAppHistory(Long project, int limit);

    @Query(value="select * from assethistory v where v.interface_id= ?1 order by v.inserted desc limit ?2", nativeQuery = true)
    List<AssetHistory> getInterfaceHistory(Long project, int limit);



}
