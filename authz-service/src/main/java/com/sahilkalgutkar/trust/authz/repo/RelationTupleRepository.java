package com.sahilkalgutkar.trust.authz.repo;

import com.sahilkalgutkar.trust.authz.domain.RelationTupleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RelationTupleRepository extends JpaRepository<RelationTupleEntity, UUID> {

    /** The hot path: every subject related to one object by one relation. */
    List<RelationTupleEntity> findByNamespaceAndObjectIdAndRelation(String namespace, String objectId,
                                                                    String relation);

    Optional<RelationTupleEntity> findByNamespaceAndObjectIdAndRelationAndSubjectTypeAndSubjectIdAndSubjectRelation(
            String namespace, String objectId, String relation,
            String subjectType, String subjectId, String subjectRelation);

    List<RelationTupleEntity> findByNamespaceAndObjectId(String namespace, String objectId);

    /**
     * The highest revision this tenant has written. Used to stamp check results, so a cached answer
     * can be compared against the revision a caller says it has already seen.
     */
    @Query("select coalesce(max(t.revision), 0) from RelationTupleEntity t")
    long currentRevision();
}
