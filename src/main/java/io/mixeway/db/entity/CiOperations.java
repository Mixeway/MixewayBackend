package io.mixeway.db.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import io.mixeway.api.cicd.model.LoadSCA;
import io.mixeway.api.protocol.cioperations.InfoScanPerformed;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.util.Date;
@Entity
@EntityScan
@Table(name = "cioperations")
@EntityListeners(AuditingEntityListener.class)
public class CiOperations {
    Long id;
    Project project;
    CodeProject codeProject;
    Date inserted;
    Date ended;
    String result;
    int vulnNumber;
    int sastCrit;
    int sastHigh;
    int openSourceCrit;
    int openSourceHigh;
    int imageCrit;
    int imageHigh;
    String commitId;
    String imageId;
    Boolean sastScan;
    Boolean openSourceScan;
    Boolean imageScan;

    public CiOperations(){}

    public CiOperations(CodeProject codeProject, InfoScanPerformed infoScanPerformed) {
        this.codeProject = codeProject;
        this.project = codeProject.getProject();
        this.commitId = infoScanPerformed.getCommitId();
        this.openSourceScan = true;
    }
    public CiOperations(CodeProject codeProject, LoadSCA loadSCA) {
        this.codeProject = codeProject;
        this.project = codeProject.getProject();
        this.commitId = loadSCA.getCommitId();
        this.openSourceScan = true;
    }


    public Date getEnded() {
        return ended;
    }

    public void setEnded(Date ended) {
        this.ended = ended;
    }

    @Column(name = "sastcrit")
    public int getSastCrit() {
        return sastCrit;
    }

    public void setSastCrit(int sastCrit) {
        this.sastCrit = sastCrit;
    }
    @Column(name = "sasthigh")
    public int getSastHigh() {
        return sastHigh;
    }

    public void setSastHigh(int sastHigh) {
        this.sastHigh = sastHigh;
    }

    @Column(name="opensourcecrit")
    public int getOpenSourceCrit() {
        return openSourceCrit;
    }

    public void setOpenSourceCrit(int openSourceCrit) {
        this.openSourceCrit = openSourceCrit;
    }
    @Column(name = "opensourcehigh")
    public int getOpenSourceHigh() {
        return openSourceHigh;
    }

    public void setOpenSourceHigh(int openSourceHigh) {
        this.openSourceHigh = openSourceHigh;
    }

    @Column(name = "imagecrit")
    public int getImageCrit() {
        return imageCrit;
    }

    public void setImageCrit(int imageCrit) {
        this.imageCrit = imageCrit;
    }

    @Column(name = "imagehigh")
    public int getImageHigh() {
        return imageHigh;
    }

    public void setImageHigh(int imageHigh) {
        this.imageHigh = imageHigh;
    }

    @Column(name = "commitid")
    public String getCommitId() {
        return commitId;
    }

    public void setCommitId(String commitId) {
        this.commitId = commitId;
    }

    @Column(name = "imageid")
    public String getImageId() {
        return imageId;
    }

    public void setImageId(String imageId) {
        this.imageId = imageId;
    }

    @Column(name = "sastscan")
    public Boolean getSastScan() {
        return sastScan;
    }

    public void setSastScan(Boolean sastScan) {
        this.sastScan = sastScan;
    }

    @Column(name = "opensourcescan")
    public Boolean getOpenSourceScan() {
        return openSourceScan;
    }

    public void setOpenSourceScan(Boolean openSourceScan) {
        this.openSourceScan = openSourceScan;
    }

    @Column(name = "imagescan")
    public Boolean getImageScan() {
        return imageScan;
    }

    public void setImageScan(Boolean imageScan) {
        this.imageScan = imageScan;
    }

    @Column(name = "vulnnumber")
    public int getVulnNumber() {
        return vulnNumber;
    }

    public void setVulnNumber(int vulnNumber) {
        this.vulnNumber = vulnNumber;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }
    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "project_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JsonIgnore
    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    @ManyToOne(fetch = FetchType.EAGER, optional = true)
    @JoinColumn(name = "codeproject_id", nullable = true)
    @OnDelete(action = OnDeleteAction.CASCADE)
    public CodeProject getCodeProject() {
        return codeProject;
    }

    public void setCodeProject(CodeProject codeProject) {
        this.codeProject = codeProject;
    }
    @CreationTimestamp
    @Temporal(TemporalType.TIMESTAMP)
    @JsonFormat(pattern = "yyyy-MM-dd hh:mm:ss")
    public Date getInserted() {
        return inserted;
    }

    public void setInserted(Date inserted) {
        this.inserted = inserted;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    @PrePersist
    public void prePersist() {
        if(sastScan == null) //We set default value in case if the value is not set yet.
            sastScan = false;
        if(imageScan == null)
            imageScan = false;
        if (openSourceScan == null)
            openSourceScan =false;
    }
    @PreUpdate
    public void preUpdate(){
        vulnNumber = sastCrit + sastHigh + openSourceCrit + openSourceHigh + imageCrit + imageHigh;
    }
}
