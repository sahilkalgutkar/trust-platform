package com.sahilkalgutkar.trust.authz.engine;

import com.sahilkalgutkar.trust.authz.config.AuthzProperties;
import com.sahilkalgutkar.trust.authz.model.NamespaceConfig;
import com.sahilkalgutkar.trust.authz.model.Rewrite;
import com.sahilkalgutkar.trust.authz.model.SubjectRef;
import com.sahilkalgutkar.trust.authz.model.UnknownRelationException;
import com.sahilkalgutkar.trust.authz.model.Zookie;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The evaluation semantics, worked through the namespace every Zanzibar example uses: documents in
 * folders, shared with people and with groups.
 */
class CheckEngineTest {

    private final AuthzProperties properties = new AuthzProperties();
    private final RecordingCache cache = new RecordingCache();

    /**
     * document: owner is direct; editor is owner-or-direct; viewer is editor-or-direct-or-inherited
     * from the parent folder. folder: viewer is direct or inherited from its own parent.
     * group: member is direct, and a member may itself be another group's member set.
     */
    private static final NamespaceConfig DOCUMENT = new NamespaceConfig("document", Map.of(
            "parent", new Rewrite.This(),
            "owner", new Rewrite.This(),
            "editor", new Rewrite.Union(List.of(
                    new Rewrite.This(),
                    new Rewrite.ComputedUserset("owner"))),
            "viewer", new Rewrite.Union(List.of(
                    new Rewrite.This(),
                    new Rewrite.ComputedUserset("editor"),
                    new Rewrite.TupleToUserset("parent", "viewer")))));

    private static final NamespaceConfig FOLDER = new NamespaceConfig("folder", Map.of(
            "parent", new Rewrite.This(),
            "viewer", new Rewrite.Union(List.of(
                    new Rewrite.This(),
                    new Rewrite.TupleToUserset("parent", "viewer")))));

    private static final NamespaceConfig GROUP = new NamespaceConfig("group", Map.of(
            "member", new Rewrite.This()));

    // ---------------------------------------------------------------- direct tuples

    @Test
    void aDirectTupleGrantsTheRelation() {
        CheckEngine engine = engine(world().tuple("document", "readme", "owner", "user:ada"));

        assertThat(allowed(engine, "document", "readme", "owner", "user:ada")).isTrue();
    }

    @Test
    void someoneWithNoTupleIsDenied() {
        CheckEngine engine = engine(world().tuple("document", "readme", "owner", "user:ada"));

        assertThat(allowed(engine, "document", "readme", "owner", "user:bob")).isFalse();
    }

    @Test
    void aTupleOnAnotherObjectDoesNotLeakAcross() {
        CheckEngine engine = engine(world().tuple("document", "readme", "owner", "user:ada"));

        assertThat(allowed(engine, "document", "roadmap", "owner", "user:ada")).isFalse();
    }

    // ---------------------------------------------------------------- computed usersets

    @Test
    void anOwnerIsAnEditorWithoutAnEditorTupleExisting() {
        CheckEngine engine = engine(world().tuple("document", "readme", "owner", "user:ada"));

        assertThat(allowed(engine, "document", "readme", "editor", "user:ada")).isTrue();
    }

    /** Two rewrites deep: owner implies editor, editor implies viewer. */
    @Test
    void anOwnerIsAViewerThroughTwoLevelsOfImplication() {
        CheckEngine engine = engine(world().tuple("document", "readme", "owner", "user:ada"));

        assertThat(allowed(engine, "document", "readme", "viewer", "user:ada")).isTrue();
    }

    @Test
    void implicationDoesNotRunBackwards() {
        CheckEngine engine = engine(world().tuple("document", "readme", "viewer", "user:bob"));

        assertThat(allowed(engine, "document", "readme", "viewer", "user:bob")).isTrue();
        assertThat(allowed(engine, "document", "readme", "editor", "user:bob")).isFalse();
        assertThat(allowed(engine, "document", "readme", "owner", "user:bob")).isFalse();
    }

    // ---------------------------------------------------------------- usersets and groups

    @Test
    void aGrantToAGroupReachesItsMembers() {
        CheckEngine engine = engine(world()
                .tuple("group", "engineering", "member", "user:ada")
                .tuple("document", "readme", "viewer", "group:engineering#member"));

        assertThat(allowed(engine, "document", "readme", "viewer", "user:ada")).isTrue();
        assertThat(allowed(engine, "document", "readme", "viewer", "user:bob")).isFalse();
    }

    @Test
    void nestedGroupsResolveTransitively() {
        CheckEngine engine = engine(world()
                .tuple("group", "everyone", "member", "group:engineering#member")
                .tuple("group", "engineering", "member", "group:backend#member")
                .tuple("group", "backend", "member", "user:ada")
                .tuple("document", "readme", "viewer", "group:everyone#member"));

        assertThat(allowed(engine, "document", "readme", "viewer", "user:ada")).isTrue();
    }

    @Test
    void removingSomeoneFromTheInnerGroupRemovesTheirAccess() {
        CheckEngine engine = engine(world()
                .tuple("group", "engineering", "member", "group:backend#member")
                .tuple("document", "readme", "viewer", "group:engineering#member"));

        assertThat(allowed(engine, "document", "readme", "viewer", "user:ada")).isFalse();
    }

    // ---------------------------------------------------------------- tuple-to-userset

    @Test
    void aDocumentInheritsViewersFromItsFolder() {
        CheckEngine engine = engine(world()
                .tuple("folder", "engineering", "viewer", "user:ada")
                .tuple("document", "readme", "parent", "folder:engineering"));

        assertThat(allowed(engine, "document", "readme", "viewer", "user:ada")).isTrue();
    }

    /** The reason nothing is materialised: re-parenting changes access with no rewrite of tuples. */
    @Test
    void inheritanceFollowsNestedFolders() {
        CheckEngine engine = engine(world()
                .tuple("folder", "company", "viewer", "user:ada")
                .tuple("folder", "engineering", "parent", "folder:company")
                .tuple("document", "readme", "parent", "folder:engineering"));

        assertThat(allowed(engine, "document", "readme", "viewer", "user:ada")).isTrue();
    }

    @Test
    void inheritanceOnlyFlowsDownwards() {
        CheckEngine engine = engine(world()
                .tuple("document", "readme", "viewer", "user:ada")
                .tuple("document", "readme", "parent", "folder:engineering"));

        assertThat(allowed(engine, "folder", "engineering", "viewer", "user:ada")).isFalse();
    }

    @Test
    void aGroupGrantedOnAFolderReachesADocumentInsideIt() {
        CheckEngine engine = engine(world()
                .tuple("group", "engineering", "member", "user:ada")
                .tuple("folder", "eng-drive", "viewer", "group:engineering#member")
                .tuple("document", "readme", "parent", "folder:eng-drive"));

        assertThat(allowed(engine, "document", "readme", "viewer", "user:ada")).isTrue();
    }

    // ---------------------------------------------------------------- set operations

    @Test
    void anIntersectionRequiresEveryBranch() {
        NamespaceConfig config = new NamespaceConfig("report", Map.of(
                "auditor", new Rewrite.This(),
                "on_call", new Rewrite.This(),
                "break_glass", new Rewrite.Intersection(List.of(
                        new Rewrite.ComputedUserset("auditor"),
                        new Rewrite.ComputedUserset("on_call")))));
        CheckEngine engine = engine(new TupleFixture().namespace(config)
                .tuple("report", "q3", "auditor", "user:ada")
                .tuple("report", "q3", "auditor", "user:bob")
                .tuple("report", "q3", "on_call", "user:ada"));

        assertThat(allowed(engine, "report", "q3", "break_glass", "user:ada")).isTrue();
        assertThat(allowed(engine, "report", "q3", "break_glass", "user:bob")).isFalse();
    }

    @Test
    void anExclusionSubtractsFromTheBase() {
        NamespaceConfig config = new NamespaceConfig("report", Map.of(
                "reader", new Rewrite.This(),
                "banned", new Rewrite.This(),
                "viewer", new Rewrite.Exclusion(
                        new Rewrite.ComputedUserset("reader"),
                        new Rewrite.ComputedUserset("banned"))));
        CheckEngine engine = engine(new TupleFixture().namespace(config)
                .tuple("report", "q3", "reader", "user:ada")
                .tuple("report", "q3", "reader", "user:bob")
                .tuple("report", "q3", "banned", "user:bob"));

        assertThat(allowed(engine, "report", "q3", "viewer", "user:ada")).isTrue();
        assertThat(allowed(engine, "report", "q3", "viewer", "user:bob")).isFalse();
    }

    @Test
    void anExclusionCannotGrantWhatTheBaseDoesNot() {
        NamespaceConfig config = new NamespaceConfig("report", Map.of(
                "reader", new Rewrite.This(),
                "banned", new Rewrite.This(),
                "viewer", new Rewrite.Exclusion(
                        new Rewrite.ComputedUserset("reader"),
                        new Rewrite.ComputedUserset("banned"))));
        CheckEngine engine = engine(new TupleFixture().namespace(config));

        assertThat(allowed(engine, "report", "q3", "viewer", "user:nobody")).isFalse();
    }

    // ---------------------------------------------------------------- safety rails

    /** A group that transitively contains itself must terminate, not overflow the stack. */
    @Test
    void aMembershipCycleTerminatesWithADenial() {
        CheckEngine engine = engine(world()
                .tuple("group", "a", "member", "group:b#member")
                .tuple("group", "b", "member", "group:a#member")
                .tuple("document", "readme", "viewer", "group:a#member"));

        assertThat(allowed(engine, "document", "readme", "viewer", "user:ada")).isFalse();
    }

    @Test
    void aCycleDoesNotHideAGrantReachableAnotherWay() {
        CheckEngine engine = engine(world()
                .tuple("group", "a", "member", "group:b#member")
                .tuple("group", "b", "member", "group:a#member")
                .tuple("group", "b", "member", "user:ada")
                .tuple("document", "readme", "viewer", "group:a#member"));

        assertThat(allowed(engine, "document", "readme", "viewer", "user:ada")).isTrue();
    }

    @Test
    void aHierarchyDeeperThanTheLimitFailsLoudlyRatherThanSlowly() {
        properties.setMaxDepth(4);
        TupleFixture world = world().tuple("folder", "f0", "viewer", "user:ada");
        for (int i = 1; i <= 10; i++) {
            world.tuple("folder", "f" + i, "parent", "folder:f" + (i - 1));
        }
        world.tuple("document", "readme", "parent", "folder:f10");
        CheckEngine engine = engine(world);

        assertThatThrownBy(() -> allowed(engine, "document", "readme", "viewer", "user:ada"))
                .isInstanceOf(CheckDepthExceededException.class)
                .hasMessageContaining("maximum evaluation depth of 4");
    }

    @Test
    void aRelationTheNamespaceDoesNotDefineIsAnErrorNotADenial() {
        CheckEngine engine = engine(world());

        assertThatThrownBy(() -> allowed(engine, "document", "readme", "administer", "user:ada"))
                .isInstanceOf(UnknownRelationException.class);
    }

    // ---------------------------------------------------------------- caching and consistency

    @Test
    void theFirstCheckEvaluatesAndTheSecondIsServedFromCache() {
        CheckEngine engine = engine(world().tuple("document", "readme", "owner", "user:ada"));

        CheckResult first = check(engine, "document", "readme", "owner", "user:ada", Zookie.of(0));
        CheckResult second = check(engine, "document", "readme", "owner", "user:ada", Zookie.of(0));

        assertThat(first.fromCache()).isFalse();
        assertThat(second.fromCache()).isTrue();
        assertThat(second.allowed()).isEqualTo(first.allowed());
    }

    /**
     * The point of the zookie: a caller that has seen revision N is never answered from a snapshot
     * older than N, so it cannot read its own permission change back stale.
     */
    @Test
    void aCacheEntryIsNotServedToACallerDemandingAFresherRevision() {
        TupleFixture world = world().tuple("document", "readme", "owner", "user:ada");
        CheckEngine engine = engine(world);
        check(engine, "document", "readme", "owner", "user:ada", Zookie.of(0));

        CheckResult afterWrite = check(engine, "document", "readme", "owner", "user:ada",
                Zookie.of(world.revision() + 5));

        assertThat(afterWrite.fromCache()).isFalse();
        assertThat(afterWrite.revision()).isEqualTo(world.revision() + 5);
    }

    @Test
    void theResultCarriesTheRevisionItReflects() {
        TupleFixture world = world().tuple("document", "readme", "owner", "user:ada");

        assertThat(check(engine(world), "document", "readme", "owner", "user:ada", Zookie.of(0))
                .revision()).isEqualTo(world.revision());
    }

    @Test
    void theResultReportsHowMuchWorkItTook() {
        CheckEngine engine = engine(world()
                .tuple("group", "engineering", "member", "user:ada")
                .tuple("document", "readme", "viewer", "group:engineering#member"));

        CheckResult result = check(engine, "document", "readme", "viewer", "user:ada", Zookie.of(0));

        assertThat(result.tuplesRead()).isPositive();
        assertThat(result.maxDepthReached()).isGreaterThan(1);
    }

    // ---------------------------------------------------------------- helpers

    private TupleFixture world() {
        return new TupleFixture().namespace(DOCUMENT).namespace(FOLDER).namespace(GROUP);
    }

    private CheckEngine engine(TupleFixture world) {
        return new CheckEngine(world.repository(), world.catalog(), cache, properties);
    }

    private static boolean allowed(CheckEngine engine, String namespace, String object,
                                   String relation, String subject) {
        return check(engine, namespace, object, relation, subject, Zookie.of(0)).allowed();
    }

    private static CheckResult check(CheckEngine engine, String namespace, String object,
                                     String relation, String subject, Zookie zookie) {
        return engine.check(TupleFixture.TENANT, namespace, object, relation,
                SubjectRef.parse(subject), zookie);
    }

    /** A real cache rather than a mock, so the revision-keying is actually exercised. */
    private static final class RecordingCache implements CheckCache {

        private final Map<String, Boolean> entries = new ConcurrentHashMap<>();

        @Override
        public Optional<Boolean> get(String key, long revision) {
            return Optional.ofNullable(entries.get(revision + "|" + key));
        }

        @Override
        public void put(String key, long revision, boolean allowed) {
            entries.put(revision + "|" + key, allowed);
        }
    }
}
