package io.mixeway.db.entity;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

/**
 * @author gsiewruk
 */
@Entity
@EntityScan
@Table(
        name = "iaasapitype",
        indexes = {
                @Index(columnList = "id",name="iaasapitype_index")
        })
@EntityListeners(AuditingEntityListener.class)
public class IaasApiType {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;
    String name;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
