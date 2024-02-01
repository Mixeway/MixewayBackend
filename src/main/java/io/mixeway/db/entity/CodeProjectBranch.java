package io.mixeway.db.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

import java.text.SimpleDateFormat;
import java.util.Date;

import static org.apache.commons.lang3.Validate.notNull;

@Entity
@EntityScan
@Table(name = "codeprojectbranch")
@EntityListeners(AuditingEntityListener.class)
public class CodeProjectBranch {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "codeproject_id", nullable = false)
    @JsonIgnore
    private CodeProject codeProject;
    private String inserted;
    private String name;

    protected CodeProjectBranch(){}

    public CodeProjectBranch(CodeProject project, String name){
        notNull(name);
        notNull(project);
        this.inserted = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
        this.name = name;
        this.codeProject = project;
    }

    public Long getId() {
        return id;
    }

    public CodeProject getCodeProject() {
        return codeProject;
    }

    public String getInserted() {
        return inserted;
    }

    public String getName() {
        return name;
    }
}
