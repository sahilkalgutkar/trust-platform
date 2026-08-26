package com.sahilkalgutkar.trust.authz.engine;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * One level of the answer to "who has this permission, and why".
 *
 * <p>Expand exists because {@code check} answers yes or no, and "why" is the question an operator
 * actually has at 3am. The tree mirrors the namespace's rewrite rules, so a surprising allow can be
 * traced to the exact tuple and the exact rule that produced it.
 *
 * @param operator {@code leaf}, {@code union}, {@code intersection}, or {@code exclusion}
 * @param subjects for a leaf: the subjects and usersets written directly against this relation
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record ExpandNode(String operator, String object, String relation, List<String> subjects,
                         List<ExpandNode> children) {

    public static ExpandNode leaf(String object, String relation, List<String> subjects) {
        return new ExpandNode("leaf", object, relation, List.copyOf(subjects), List.of());
    }

    public static ExpandNode operator(String operator, String object, String relation,
                                      List<ExpandNode> children) {
        return new ExpandNode(operator, object, relation, List.of(), List.copyOf(children));
    }
}
