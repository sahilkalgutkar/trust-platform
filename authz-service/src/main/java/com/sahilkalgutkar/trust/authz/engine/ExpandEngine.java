package com.sahilkalgutkar.trust.authz.engine;

import com.sahilkalgutkar.trust.authz.config.AuthzProperties;
import com.sahilkalgutkar.trust.authz.domain.RelationTupleEntity;
import com.sahilkalgutkar.trust.authz.model.NamespaceConfig;
import com.sahilkalgutkar.trust.authz.model.Rewrite;
import com.sahilkalgutkar.trust.authz.model.SubjectRef;
import com.sahilkalgutkar.trust.authz.repo.RelationTupleRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Builds the "why" tree for one object and relation. */
@Service
public class ExpandEngine {

    private final RelationTupleRepository tupleRepository;
    private final NamespaceCatalog namespaceCatalog;
    private final AuthzProperties properties;

    public ExpandEngine(RelationTupleRepository tupleRepository, NamespaceCatalog namespaceCatalog,
                        AuthzProperties properties) {
        this.tupleRepository = tupleRepository;
        this.namespaceCatalog = namespaceCatalog;
        this.properties = properties;
    }

    @Transactional(readOnly = true)
    public ExpandNode expand(UUID tenantId, String namespace, String objectId, String relation) {
        return expand(tenantId, namespace, objectId, relation, new HashSet<>(), 0);
    }

    private ExpandNode expand(UUID tenantId, String namespace, String objectId, String relation,
                              Set<String> visited, int depth) {
        if (depth > properties.getMaxDepth()) {
            throw new CheckDepthExceededException(properties.getMaxDepth());
        }
        String node = namespace + ":" + objectId + "#" + relation;
        if (!visited.add(node)) {
            // A cycle is reported as an empty leaf rather than followed. The tree is for a human to
            // read, and an infinitely deep one helps nobody.
            return ExpandNode.leaf(node, relation, List.of());
        }
        try {
            NamespaceConfig config = namespaceCatalog.require(tenantId, namespace);
            return expandRewrite(tenantId, config.rewriteFor(relation), namespace, objectId, relation,
                    visited, depth);
        } finally {
            visited.remove(node);
        }
    }

    private ExpandNode expandRewrite(UUID tenantId, Rewrite rewrite, String namespace, String objectId,
                                     String relation, Set<String> visited, int depth) {
        String object = namespace + ":" + objectId;
        return switch (rewrite) {
            case Rewrite.This ignored -> ExpandNode.leaf(object, relation,
                    directSubjects(namespace, objectId, relation));

            case Rewrite.ComputedUserset computed -> ExpandNode.operator("union", object, relation,
                    List.of(expand(tenantId, namespace, objectId, computed.relation(), visited, depth + 1)));

            case Rewrite.TupleToUserset tupleToUserset -> {
                List<ExpandNode> children = new ArrayList<>();
                for (RelationTupleEntity tuple : tupleRepository
                        .findByNamespaceAndObjectIdAndRelation(namespace, objectId, tupleToUserset.tupleset())) {
                    SubjectRef related = tuple.subject();
                    String targetRelation = related.isUserset()
                            ? related.relation()
                            : tupleToUserset.computedUserset();
                    children.add(expand(tenantId, related.type(), related.id(), targetRelation,
                            visited, depth + 1));
                }
                yield ExpandNode.operator("union", object, relation, children);
            }

            case Rewrite.Union union -> ExpandNode.operator("union", object, relation,
                    expandAll(tenantId, union.children(), namespace, objectId, relation, visited, depth));

            case Rewrite.Intersection intersection -> ExpandNode.operator("intersection", object, relation,
                    expandAll(tenantId, intersection.children(), namespace, objectId, relation, visited, depth));

            case Rewrite.Exclusion exclusion -> ExpandNode.operator("exclusion", object, relation, List.of(
                    expandRewrite(tenantId, exclusion.base(), namespace, objectId, relation, visited, depth),
                    expandRewrite(tenantId, exclusion.subtract(), namespace, objectId, relation, visited, depth)));
        };
    }

    private List<ExpandNode> expandAll(UUID tenantId, List<Rewrite> rewrites, String namespace,
                                       String objectId, String relation, Set<String> visited, int depth) {
        return rewrites.stream()
                .map(child -> expandRewrite(tenantId, child, namespace, objectId, relation, visited, depth))
                .toList();
    }

    private List<String> directSubjects(String namespace, String objectId, String relation) {
        return tupleRepository.findByNamespaceAndObjectIdAndRelation(namespace, objectId, relation)
                .stream()
                .map(tuple -> tuple.subject().toString())
                .sorted()
                .toList();
    }
}
