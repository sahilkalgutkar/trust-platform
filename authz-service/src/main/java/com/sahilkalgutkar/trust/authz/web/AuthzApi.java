package com.sahilkalgutkar.trust.authz.web;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.sahilkalgutkar.trust.authz.engine.ExpandNode;
import com.sahilkalgutkar.trust.authz.engine.TupleChange;
import com.sahilkalgutkar.trust.authz.model.Rewrite;
import com.sahilkalgutkar.trust.authz.model.SubjectRef;
import jakarta.validation.constraints.NotBlank;

import java.util.List;
import java.util.Map;

/** Request and response shapes for the authorization API. */
public final class AuthzApi {

    private AuthzApi() {
    }

    public record CheckRequest(
            @NotBlank String namespace,
            @NotBlank String object,
            @NotBlank String relation,
            @NotBlank String subject,
            /** The revision the caller has already observed; omit for "whatever is current". */
            String zookie) {

        public SubjectRef subjectRef() {
            return SubjectRef.parse(subject);
        }
    }

    /**
     * @param cached whether this answer came from the check cache — surfaced rather than hidden,
     *               because "is my cache doing anything" is otherwise unanswerable from outside
     */
    public record CheckResponse(boolean allowed, String zookie, boolean cached, int tuplesRead,
                                int depth) {
    }

    public record ExpandRequest(@NotBlank String namespace, @NotBlank String object,
                                @NotBlank String relation) {
    }

    public record ExpandResponse(ExpandNode tree) {
    }

    public record WriteRequest(List<Change> changes) {

        public List<TupleChange> toChanges() {
            if (changes == null) {
                return List.of();
            }
            return changes.stream().map(Change::toChange).toList();
        }
    }

    public record Change(String operation, String namespace, String object, String relation,
                         String subject) {

        public TupleChange toChange() {
            TupleChange.Operation parsed;
            try {
                parsed = TupleChange.Operation.valueOf(
                        operation == null ? "" : operation.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("operation must be WRITE or DELETE, got: " + operation);
            }
            return new TupleChange(parsed, namespace, object, relation, SubjectRef.parse(subject));
        }
    }

    public record WriteResponse(String zookie, int applied) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record NamespaceRequest(@NotBlank String name, Map<String, Rewrite> relations) {
    }

    public record NamespaceResponse(String name, Map<String, Rewrite> relations) {
    }
}
