package com.sahilkalgutkar.trust.authz.engine;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sahilkalgutkar.trust.authz.domain.NamespaceEntity;
import com.sahilkalgutkar.trust.authz.model.NamespaceConfig;
import com.sahilkalgutkar.trust.authz.model.Rewrite;
import com.sahilkalgutkar.trust.authz.repo.NamespaceRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class NamespaceCatalogTest {

    private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");

    private final NamespaceRepository repository = mock(NamespaceRepository.class);
    private final NamespaceCatalog catalog = new NamespaceCatalog(repository, new ObjectMapper(),
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void aStoredNamespaceRoundTripsThroughJson() {
        NamespaceConfig config = new NamespaceConfig("document", Map.of(
                "owner", new Rewrite.This(),
                "viewer", new Rewrite.Union(List.of(
                        new Rewrite.This(),
                        new Rewrite.ComputedUserset("owner"),
                        new Rewrite.TupleToUserset("owner", "viewer")))));
        when(repository.findByTenantIdAndName(TENANT, "document")).thenReturn(Optional.empty());

        catalog.save(TENANT, config);

        ArgumentCaptor<NamespaceEntity> saved = ArgumentCaptor.forClass(NamespaceEntity.class);
        verify(repository).save(saved.capture());
        when(repository.findByTenantIdAndName(TENANT, "document"))
                .thenReturn(Optional.of(saved.getValue()));

        assertThat(catalog.require(TENANT, "document")).isEqualTo(config);
    }

    @Test
    void savingAnExistingNamespaceUpdatesItRatherThanInsertingASecond() {
        NamespaceEntity existing = new NamespaceEntity(TENANT, "document", "{}");
        when(repository.findByTenantIdAndName(TENANT, "document")).thenReturn(Optional.of(existing));

        catalog.save(TENANT, new NamespaceConfig("document", Map.of("owner", new Rewrite.This())));

        verify(repository, org.mockito.Mockito.never()).save(any());
        assertThat(existing.getConfig()).contains("owner");
        assertThat(existing.getUpdatedAt()).isEqualTo(NOW);
    }

    @Test
    void anAbsentNamespaceIsReportedRatherThanReturnedEmpty() {
        when(repository.findByTenantIdAndName(any(), anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> catalog.require(TENANT, "ghost"))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessageContaining("ghost");
    }

    // ---------------------------------------------------------------- configuration validation

    @Test
    void aRewriteReferencingAnUndefinedRelationIsRejectedAtWriteTime() {
        assertThatThrownBy(() -> NamespaceCatalog.validate(new NamespaceConfig("document", Map.of(
                "viewer", new Rewrite.ComputedUserset("editor")))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not define");
    }

    @Test
    void aTuplesetReferencingAnUndefinedRelationIsRejected() {
        assertThatThrownBy(() -> NamespaceCatalog.validate(new NamespaceConfig("document", Map.of(
                "viewer", new Rewrite.TupleToUserset("parent", "viewer")))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("walks tupleset");
    }

    @Test
    void danglingReferencesAreCaughtInsideNestedOperators() {
        assertThatThrownBy(() -> NamespaceCatalog.validate(new NamespaceConfig("document", Map.of(
                "owner", new Rewrite.This(),
                "viewer", new Rewrite.Union(List.of(
                        new Rewrite.This(),
                        new Rewrite.Intersection(List.of(
                                new Rewrite.ComputedUserset("owner"),
                                new Rewrite.ComputedUserset("nonexistent")))))))))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> NamespaceCatalog.validate(new NamespaceConfig("document", Map.of(
                "owner", new Rewrite.This(),
                "viewer", new Rewrite.Exclusion(
                        new Rewrite.ComputedUserset("owner"),
                        new Rewrite.ComputedUserset("nonexistent"))))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** The computed relation of a tupleToUserset lives in another namespace, so it is not checkable here. */
    @Test
    void aTupleToUsersetMayNameARelationThatBelongsToAnotherNamespace() {
        assertThatCode(() -> NamespaceCatalog.validate(new NamespaceConfig("document", Map.of(
                "parent", new Rewrite.This(),
                "viewer", new Rewrite.TupleToUserset("parent", "viewer-over-in-folder")))))
                .doesNotThrowAnyException();
    }

    @Test
    void aWellFormedNamespaceValidates() {
        assertThatCode(() -> NamespaceCatalog.validate(new NamespaceConfig("document", Map.of(
                "parent", new Rewrite.This(),
                "owner", new Rewrite.This(),
                "viewer", new Rewrite.Union(List.of(
                        new Rewrite.This(),
                        new Rewrite.ComputedUserset("owner"),
                        new Rewrite.TupleToUserset("parent", "viewer")))))))
                .doesNotThrowAnyException();
    }

    @Test
    void listingReturnsTheTenantsNamespaceNames() {
        when(repository.findByTenantId(TENANT)).thenReturn(List.of(
                new NamespaceEntity(TENANT, "document", "{}"),
                new NamespaceEntity(TENANT, "folder", "{}")));

        assertThat(catalog.names(TENANT)).containsExactly("document", "folder");
    }

    @Test
    void anUnreadableStoredConfigurationFailsLoudly() {
        when(repository.findByTenantIdAndName(TENANT, "broken"))
                .thenReturn(Optional.of(new NamespaceEntity(TENANT, "broken", "{not json")));

        assertThatThrownBy(() -> catalog.require(TENANT, "broken"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("unreadable");
    }
}
