package io.mixeway.db.repository;

import io.mixeway.db.entity.IaasApiType;
import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import io.mixeway.db.entity.IaasApi;

import java.util.List;
import java.util.Optional;

@Repository
public interface IaasApiRepository extends JpaRepository<IaasApi,Long>{

    List<IaasApi> findByStatus(Boolean status);
    List<IaasApi> findByStatusAndEnabled(Boolean status, Boolean enabled);
    Optional<IaasApi> findByProjectAndIaasApiType(Project project, IaasApiType type);
}
