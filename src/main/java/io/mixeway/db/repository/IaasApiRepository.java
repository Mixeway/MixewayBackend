package io.mixeway.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import io.mixeway.db.entity.IaasApi;

@Repository
public interface IaasApiRepository extends JpaRepository<IaasApi,Long>{

}
