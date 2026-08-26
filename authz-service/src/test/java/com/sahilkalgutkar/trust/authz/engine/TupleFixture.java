package com.sahilkalgutkar.trust.authz.engine;

import com.sahilkalgutkar.trust.authz.domain.RelationTupleEntity;
import com.sahilkalgutkar.trust.authz.model.NamespaceConfig;
import com.sahilkalgutkar.trust.authz.model.SubjectRef;
import com.sahilkalgutkar.trust.authz.repo.RelationTupleRepository;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An in-memory world of tuples and namespaces for the engine tests.
 *
 * <p>The repository is a mock whose answer filters a real list rather than a set of stubbed return
 * values: what these tests exercise is a recursive walk over relationships, and stubbing each hop
 * individually would encode the expected traversal into the test instead of checking it.
 */
final class TupleFixture {

    static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");

    private final List<RelationTupleEntity> tuples = new ArrayList<>();
    private final Map<String, NamespaceConfig> namespaces = new HashMap<>();
    private long revision;

    RelationTupleRepository repository() {
        RelationTupleRepository repository = mock(RelationTupleRepository.class);
        when(repository.findByNamespaceAndObjectIdAndRelation(anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> tuples.stream()
                        .filter(t -> t.getNamespace().equals(invocation.getArgument(0)))
                        .filter(t -> t.getObjectId().equals(invocation.getArgument(1)))
                        .filter(t -> t.getRelation().equals(invocation.getArgument(2)))
                        .toList());
        when(repository.currentRevision()).thenAnswer(invocation -> revision);
        return repository;
    }

    NamespaceCatalog catalog() {
        NamespaceCatalog catalog = mock(NamespaceCatalog.class);
        when(catalog.require(org.mockito.ArgumentMatchers.any(), anyString()))
                .thenAnswer(invocation -> {
                    String name = invocation.getArgument(1);
                    NamespaceConfig config = namespaces.get(name);
                    if (config == null) {
                        throw new java.util.NoSuchElementException("No namespace '" + name + "'");
                    }
                    return config;
                });
        return catalog;
    }

    TupleFixture namespace(NamespaceConfig config) {
        namespaces.put(config.name(), config);
        return this;
    }

    /** {@code tuple("document", "readme", "viewer", "user:ada")} */
    TupleFixture tuple(String namespace, String object, String relation, String subject) {
        revision++;
        tuples.add(new RelationTupleEntity(UUID.randomUUID(), namespace, object, relation,
                SubjectRef.parse(subject), revision));
        return this;
    }

    long revision() {
        return revision;
    }
}
