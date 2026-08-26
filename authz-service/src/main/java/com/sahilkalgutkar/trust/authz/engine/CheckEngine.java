package com.sahilkalgutkar.trust.authz.engine;

import com.sahilkalgutkar.trust.authz.config.AuthzProperties;
import com.sahilkalgutkar.trust.authz.domain.RelationTupleEntity;
import com.sahilkalgutkar.trust.authz.model.NamespaceConfig;
import com.sahilkalgutkar.trust.authz.model.Rewrite;
import com.sahilkalgutkar.trust.authz.model.SubjectRef;
import com.sahilkalgutkar.trust.authz.model.Zookie;
import com.sahilkalgutkar.trust.authz.repo.RelationTupleRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Evaluates a permission question against the tuples and the namespace's rewrite rules.
 *
 * <p>The evaluation is depth-first and short-circuiting, which is the right shape for the question
 * being asked: "is this allowed" needs one path to succeed, not every path enumerated. Two
 * safeguards keep a hostile or merely careless namespace from turning a check into an outage — a
 * visited set that makes cycles terminate with a denial rather than a stack overflow, and a depth
 * limit for hierarchies that are finite but absurd.
 *
 * <p>What this does <em>not</em> do, and a production Zanzibar does: parallelise the branches of a
 * union, batch tuple reads across recursion levels, or maintain the leopard index that makes deeply
 * nested group membership cheap. Those are throughput concerns, and they would obscure the part
 * worth reading here, which is the semantics.
 */
@Service
public class CheckEngine {

    private final RelationTupleRepository tupleRepository;
    private final NamespaceCatalog namespaceCatalog;
    private final CheckCache cache;
    private final AuthzProperties properties;

    public CheckEngine(RelationTupleRepository tupleRepository, NamespaceCatalog namespaceCatalog,
                       CheckCache cache, AuthzProperties properties) {
        this.tupleRepository = tupleRepository;
        this.namespaceCatalog = namespaceCatalog;
        this.cache = cache;
        this.properties = properties;
    }

    @Transactional(readOnly = true)
    public CheckResult check(UUID tenantId, String namespace, String objectId, String relation,
                             SubjectRef subject, Zookie atLeastAsFresh) {
        long revision = Math.max(tupleRepository.currentRevision(), atLeastAsFresh.revision());
        String cacheKey = cacheKey(tenantId, namespace, objectId, relation, subject);

        Optional<Boolean> cached = cache.get(cacheKey, revision);
        if (cached.isPresent()) {
            return CheckResult.cached(cached.get(), revision);
        }

        Evaluation evaluation = new Evaluation(tenantId);
        boolean allowed = evaluate(namespace, objectId, relation, subject, evaluation);

        cache.put(cacheKey, revision, allowed);
        return new CheckResult(allowed, revision, false, evaluation.tuplesRead, evaluation.maxDepth);
    }

    private boolean evaluate(String namespace, String objectId, String relation, SubjectRef subject,
                             Evaluation evaluation) {
        String node = namespace + ":" + objectId + "#" + relation + "@" + subject;
        // A namespace can describe a cycle — a group that contains itself, transitively. Returning
        // false for a node already on the current path is not a guess: if membership held for any
        // other reason, some other branch would have found it without going round again.
        if (!evaluation.visited.add(node)) {
            return false;
        }
        evaluation.enter(properties.getMaxDepth());
        try {
            NamespaceConfig config = namespaceCatalog.require(evaluation.tenantId, namespace);
            return evaluateRewrite(config.rewriteFor(relation), namespace, objectId, relation,
                    subject, evaluation);
        } finally {
            evaluation.exit();
            evaluation.visited.remove(node);
        }
    }

    private boolean evaluateRewrite(Rewrite rewrite, String namespace, String objectId, String relation,
                                    SubjectRef subject, Evaluation evaluation) {
        return switch (rewrite) {
            case Rewrite.This ignored -> matchesDirectTuple(namespace, objectId, relation, subject, evaluation);

            // "Anyone who holds <relation> on this same object" — the editor-implies-viewer case.
            case Rewrite.ComputedUserset computed ->
                    evaluate(namespace, objectId, computed.relation(), subject, evaluation);

            case Rewrite.TupleToUserset tupleToUserset ->
                    walkToRelatedObjects(tupleToUserset, namespace, objectId, subject, evaluation);

            case Rewrite.Union union -> union.children().stream()
                    .anyMatch(child -> evaluateRewrite(child, namespace, objectId, relation, subject, evaluation));

            case Rewrite.Intersection intersection -> intersection.children().stream()
                    .allMatch(child -> evaluateRewrite(child, namespace, objectId, relation, subject, evaluation));

            // The only deny in the model, and deliberately the only one: a single subtraction is
            // reasonable to reason about, whereas arbitrary deny rules interacting with inheritance
            // are how permission systems become impossible to explain to an auditor.
            case Rewrite.Exclusion exclusion ->
                    evaluateRewrite(exclusion.base(), namespace, objectId, relation, subject, evaluation)
                            && !evaluateRewrite(exclusion.subtract(), namespace, objectId, relation, subject, evaluation);
        };
    }

    private boolean matchesDirectTuple(String namespace, String objectId, String relation,
                                       SubjectRef subject, Evaluation evaluation) {
        List<RelationTupleEntity> tuples =
                tupleRepository.findByNamespaceAndObjectIdAndRelation(namespace, objectId, relation);
        evaluation.tuplesRead += tuples.size();

        for (RelationTupleEntity tuple : tuples) {
            SubjectRef related = tuple.subject();
            if (!related.isUserset()) {
                if (related.equals(subject)) {
                    return true;
                }
                continue;
            }
            // The tuple grants to a *set* of subjects (group:eng#member), so membership of that set
            // is itself a check — which is what makes nested groups work with no extra machinery.
            if (evaluate(related.type(), related.id(), related.relation(), subject, evaluation)) {
                return true;
            }
        }
        return false;
    }

    private boolean walkToRelatedObjects(Rewrite.TupleToUserset rule, String namespace, String objectId,
                                         SubjectRef subject, Evaluation evaluation) {
        List<RelationTupleEntity> tuples = tupleRepository
                .findByNamespaceAndObjectIdAndRelation(namespace, objectId, rule.tupleset());
        evaluation.tuplesRead += tuples.size();

        for (RelationTupleEntity tuple : tuples) {
            SubjectRef related = tuple.subject();
            // A tupleset entry normally names an object (folder:engineering) and the rule supplies
            // the relation to evaluate there. If the tuple already names a relation, it wins —
            // that is how one object can inherit a *different* relation than the rule's default.
            String targetRelation = related.isUserset() ? related.relation() : rule.computedUserset();
            if (evaluate(related.type(), related.id(), targetRelation, subject, evaluation)) {
                return true;
            }
        }
        return false;
    }

    static String cacheKey(UUID tenantId, String namespace, String objectId, String relation,
                           SubjectRef subject) {
        return tenantId + "|" + namespace + ":" + objectId + "#" + relation + "@" + subject;
    }

    /** Per-check mutable state: the cycle guard, the depth counter, and the tuple tally. */
    private static final class Evaluation {

        private final UUID tenantId;
        private final Set<String> visited = new HashSet<>();
        private int depth;
        private int maxDepth;
        private int tuplesRead;

        private Evaluation(UUID tenantId) {
            this.tenantId = tenantId;
        }

        private void enter(int limit) {
            depth++;
            maxDepth = Math.max(maxDepth, depth);
            if (depth > limit) {
                throw new CheckDepthExceededException(limit);
            }
        }

        private void exit() {
            depth--;
        }
    }
}
