package io.mixeway.db.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import io.mixeway.db.entity.Activity;

public interface ActivityRepository extends JpaRepository<Activity, Long>{
	
	public List<Activity> findTop10ByOrderByIdDesc();

}
