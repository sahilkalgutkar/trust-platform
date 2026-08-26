package com.sahilkalgutkar.trust.authz.domain;

import com.sahilkalgutkar.trust.authz.model.SubjectRef;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.TenantId;

import java.time.Instant;
import java.util.UUID;

/** One relationship: {@code namespace:object#relation@subject}. */
@Entity
@Table(name = "relation_tuples")
public class RelationTupleEntity {

    @Id
    private UUID id;

    @TenantId
    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(nullable = false)
    private String namespace;

    @Column(name = "object_id", nullable = false)
    private String objectId;

    @Column(nullable = false)
    private String relation;

    @Column(name = "subject_type", nullable = false)
    private String subjectType;

    @Column(name = "subject_id", nullable = false)
    private String subjectId;

    @Column(name = "subject_relation", nullable = false)
    private String subjectRelation = "";

    @Column(nullable = false)
    private long revision;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected RelationTupleEntity() {
    }

    public RelationTupleEntity(UUID id, String namespace, String objectId, String relation,
                               SubjectRef subject, long revision) {
        this.id = id;
        this.namespace = namespace;
        this.objectId = objectId;
        this.relation = relation;
        this.subjectType = subject.type();
        this.subjectId = subject.id();
        this.subjectRelation = subject.relation();
        this.revision = revision;
    }

    public SubjectRef subject() {
        return new SubjectRef(subjectType, subjectId, subjectRelation);
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getNamespace() {
        return namespace;
    }

    public String getObjectId() {
        return objectId;
    }

    public String getRelation() {
        return relation;
    }

    public String getSubjectType() {
        return subjectType;
    }

    public String getSubjectId() {
        return subjectId;
    }

    public String getSubjectRelation() {
        return subjectRelation;
    }

    public long getRevision() {
        return revision;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
