/*
 * @created  2020-10-28 : 09:23
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.db.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

@Entity
@EntityScan
@Table(name = "cxbranch")
@EntityListeners(AuditingEntityListener.class)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CxBranch {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "codeproject_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    CodeProject codeProject;
    String branch;
    int cxid;

    public CxBranch(){}

    public CxBranch(CodeProject codeProject, String branch){
        this.branch = branch;
        this.codeProject = codeProject;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public CodeProject getCodeProject() {
        return codeProject;
    }

    public void setCodeProject(CodeProject codeProject) {
        this.codeProject = codeProject;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public int getCxid() {
        return cxid;
    }

    public void setCxid(int cxid) {
        this.cxid = cxid;
    }
}
