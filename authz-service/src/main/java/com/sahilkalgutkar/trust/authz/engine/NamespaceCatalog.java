package com.sahilkalgutkar.trust.authz.engine;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sahilkalgutkar.trust.authz.domain.NamespaceEntity;
import com.sahilkalgutkar.trust.authz.model.NamespaceConfig;
import com.sahilkalgutkar.trust.authz.model.Rewrite;
import com.sahilkalgutkar.trust.authz.repo.NamespaceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

/** Reads and writes namespace configurations, and validates them before they are stored. */
@Service
public class NamespaceCatalog {

    private static final TypeReference<Map<String, Rewrite>> RELATIONS_TYPE = new TypeReference<>() {
    };

    private final NamespaceRepository repository;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public NamespaceCatalog(NamespaceRepository repository, ObjectMapper objectMapper, Clock clock) {
        this.repository = repository;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public NamespaceConfig require(UUID tenantId, String name) {
        return repository.findByTenantIdAndName(tenantId, name)
                .map(this::deserialize)
                .orElseThrow(() -> new NoSuchElementException("No namespace '" + name + "' in this tenant"));
    }

    @Transactional(readOnly = true)
    public List<String> names(UUID tenantId) {
        return repository.findByTenantId(tenantId).stream().map(NamespaceEntity::getName).toList();
    }

    @Transactional
    public NamespaceConfig save(UUID tenantId, NamespaceConfig config) {
        validate(config);
        String json = serialize(config.relations());
        repository.findByTenantIdAndName(tenantId, config.name())
                .ifPresentOrElse(
                        existing -> existing.update(json, clock.instant()),
                        () -> repository.save(new NamespaceEntity(tenantId, config.name(), json)));
        return config;
    }

    /**
     * Rejects a configuration whose rewrites reference relations that do not exist.
     *
     * <p>Catching this at write time rather than at check time matters: an unresolvable reference
     * discovered during a check is an error on a request that had nothing to do with it, raised
     * against whoever happened to ask, long after whoever broke it has moved on.
     */
    static void validate(NamespaceConfig config) {
        config.relations().forEach((relation, rewrite) ->
                validateRewrite(config, relation, rewrite));
    }

    private static void validateRewrite(NamespaceConfig config, String relation, Rewrite rewrite) {
        switch (rewrite) {
            case Rewrite.This ignored -> {
            }
            case Rewrite.ComputedUserset computed -> {
                if (!config.defines(computed.relation())) {
                    throw new IllegalArgumentException("Relation '" + relation + "' references '"
                            + computed.relation() + "', which this namespace does not define");
                }
            }
            // The tupleset relation must exist locally; the computed one lives in whatever
            // namespace the tupleset points at, so it cannot be checked from here.
            case Rewrite.TupleToUserset tupleToUserset -> {
                if (!config.defines(tupleToUserset.tupleset())) {
                    throw new IllegalArgumentException("Relation '" + relation + "' walks tupleset '"
                            + tupleToUserset.tupleset() + "', which this namespace does not define");
                }
            }
            case Rewrite.Union union -> union.children()
                    .forEach(child -> validateRewrite(config, relation, child));
            case Rewrite.Intersection intersection -> intersection.children()
                    .forEach(child -> validateRewrite(config, relation, child));
            case Rewrite.Exclusion exclusion -> {
                validateRewrite(config, relation, exclusion.base());
                validateRewrite(config, relation, exclusion.subtract());
            }
        }
    }

    private NamespaceConfig deserialize(NamespaceEntity entity) {
        try {
            Map<String, Rewrite> relations = objectMapper.readValue(entity.getConfig(), RELATIONS_TYPE);
            return new NamespaceConfig(entity.getName(), relations);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Stored namespace '" + entity.getName() + "' is unreadable", e);
        }
    }

    private String serialize(Map<String, Rewrite> relations) {
        try {
            // writerFor rather than writeValueAsString: handed a bare Map, Jackson serializes each
            // value by its runtime class and omits the polymorphic type id, so a `this` rewrite
            // round-trips out as an untagged {} that cannot be read back. Naming the declared type
            // is what makes the tags appear.
            return objectMapper.writerFor(RELATIONS_TYPE).writeValueAsString(relations);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException("Namespace configuration is not serializable", e);
        }
    }
}
