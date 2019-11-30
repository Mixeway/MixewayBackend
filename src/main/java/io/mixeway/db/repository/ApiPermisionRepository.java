package io.mixeway.db.repository;

import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.ApiPermision;
import io.mixeway.db.entity.ApiType;

public interface ApiPermisionRepository extends JpaRepository<ApiPermision, Long> {
	ApiPermision findByProjectAndApiType(Project project, ApiType apiType);

}
