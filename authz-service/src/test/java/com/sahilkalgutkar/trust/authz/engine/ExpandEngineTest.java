package com.sahilkalgutkar.trust.authz.engine;

import com.sahilkalgutkar.trust.authz.config.AuthzProperties;
import com.sahilkalgutkar.trust.authz.model.NamespaceConfig;
import com.sahilkalgutkar.trust.authz.model.Rewrite;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Expand answers "who, and why" — the question a denial dispute actually turns on. */
class ExpandEngineTest {

    private static final NamespaceConfig DOCUMENT = new NamespaceConfig("document", Map.of(
            "parent", new Rewrite.This(),
            "owner", new Rewrite.This(),
            "viewer", new Rewrite.Union(List.of(
                    new Rewrite.This(),
                    new Rewrite.ComputedUserset("owner"),
                    new Rewrite.TupleToUserset("parent", "viewer")))));

    private static final NamespaceConfig FOLDER = new NamespaceConfig("folder", Map.of(
            "viewer", new Rewrite.This()));

    private final AuthzProperties properties = new AuthzProperties();

    @Test
    void aLeafListsTheSubjectsWrittenDirectly() {
        ExpandNode tree = engine(world()
                .tuple("document", "readme", "owner", "user:ada")
                .tuple("document", "readme", "owner", "user:bob"))
                .expand(TupleFixture.TENANT, "document", "readme", "owner");

        assertThat(tree.operator()).isEqualTo("leaf");
        assertThat(tree.subjects()).containsExactly("user:ada", "user:bob");
    }

    @Test
    void aUnionShowsEveryBranchThatCouldGrantAccess() {
        ExpandNode tree = engine(world()
                .tuple("document", "readme", "viewer", "user:carol")
                .tuple("document", "readme", "owner", "user:ada")
                .tuple("document", "readme", "parent", "folder:engineering")
                .tuple("folder", "engineering", "viewer", "user:dave"))
                .expand(TupleFixture.TENANT, "document", "readme", "viewer");

        assertThat(tree.operator()).isEqualTo("union");
        assertThat(flatten(tree)).contains("user:carol", "user:ada", "user:dave");
    }

    @Test
    void usersetsAppearAsThemselvesRatherThanBeingSilentlyExpandedAway() {
        ExpandNode tree = engine(world()
                .tuple("document", "readme", "viewer", "group:engineering#member"))
                .expand(TupleFixture.TENANT, "document", "readme", "viewer");

        assertThat(flatten(tree)).contains("group:engineering#member");
    }

    @Test
    void anExclusionKeepsBothSidesVisible() {
        NamespaceConfig config = new NamespaceConfig("report", Map.of(
                "reader", new Rewrite.This(),
                "banned", new Rewrite.This(),
                "viewer", new Rewrite.Exclusion(
                        new Rewrite.ComputedUserset("reader"),
                        new Rewrite.ComputedUserset("banned"))));
        ExpandNode tree = engine(new TupleFixture().namespace(config)
                .tuple("report", "q3", "reader", "user:ada")
                .tuple("report", "q3", "banned", "user:bob"))
                .expand(TupleFixture.TENANT, "report", "q3", "viewer");

        assertThat(tree.operator()).isEqualTo("exclusion");
        assertThat(flatten(tree)).contains("user:ada", "user:bob");
    }

    @Test
    void aCycleIsCutRatherThanFollowedForever() {
        NamespaceConfig group = new NamespaceConfig("group", Map.of("member", new Rewrite.This()));
        NamespaceConfig looping = new NamespaceConfig("loop", Map.of(
                "parent", new Rewrite.This(),
                "viewer", new Rewrite.TupleToUserset("parent", "viewer")));
        ExpandNode tree = engine(new TupleFixture().namespace(group).namespace(looping)
                .tuple("loop", "a", "parent", "loop:b")
                .tuple("loop", "b", "parent", "loop:a"))
                .expand(TupleFixture.TENANT, "loop", "a", "viewer");

        assertThat(tree).isNotNull();
    }

    @Test
    void anAbsurdlyDeepHierarchyStopsAtTheDepthLimit() {
        properties.setMaxDepth(3);
        NamespaceConfig looping = new NamespaceConfig("chain", Map.of(
                "parent", new Rewrite.This(),
                "viewer", new Rewrite.TupleToUserset("parent", "viewer")));
        TupleFixture world = new TupleFixture().namespace(looping);
        for (int i = 1; i <= 10; i++) {
            world.tuple("chain", "c" + i, "parent", "chain:c" + (i - 1));
        }

        assertThatThrownBy(() -> engine(world).expand(TupleFixture.TENANT, "chain", "c10", "viewer"))
                .isInstanceOf(CheckDepthExceededException.class);
    }

    private TupleFixture world() {
        return new TupleFixture().namespace(DOCUMENT).namespace(FOLDER);
    }

    private ExpandEngine engine(TupleFixture world) {
        return new ExpandEngine(world.repository(), world.catalog(), properties);
    }

    private static List<String> flatten(ExpandNode node) {
        return java.util.stream.Stream.concat(
                node.subjects().stream(),
                node.children().stream().flatMap(child -> flatten(child).stream())).toList();
    }
}
