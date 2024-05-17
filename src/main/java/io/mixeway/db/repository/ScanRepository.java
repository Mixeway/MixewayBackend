package io.mixeway.db.repository;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Scan;
import io.mixeway.db.entity.WebApp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {
    List<Scan> findByCodeProject(CodeProject codeProject);
    List<Scan> findByWebapp(WebApp webApp);
    List<Scan> findByInterfaceObj(Interface anInterface);
}
