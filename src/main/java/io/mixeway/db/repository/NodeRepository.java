package io.mixeway.db.repository;

import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import io.mixeway.db.entity.Node;

public interface NodeRepository extends JpaRepository<Node, Long> {
	Node findByProjectAndNameAndType(Project project, String name, String type);
	Node findByProjectAndName(Project project, String name);

}
