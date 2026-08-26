package com.sahilkalgutkar.trust.authz.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SubjectRefTest {

    @Test
    void aConcreteSubjectParsesFromTypeColonId() {
        SubjectRef subject = SubjectRef.parse("user:ada");

        assertThat(subject.type()).isEqualTo("user");
        assertThat(subject.id()).isEqualTo("ada");
        assertThat(subject.relation()).isEmpty();
        assertThat(subject.isUserset()).isFalse();
        assertThat(subject).hasToString("user:ada");
    }

    @Test
    void aUsersetParsesFromTypeColonIdHashRelation() {
        SubjectRef userset = SubjectRef.parse("group:engineering#member");

        assertThat(userset.type()).isEqualTo("group");
        assertThat(userset.id()).isEqualTo("engineering");
        assertThat(userset.relation()).isEqualTo("member");
        assertThat(userset.isUserset()).isTrue();
        assertThat(userset).hasToString("group:engineering#member");
    }

    @Test
    void anIdContainingAColonSurvivesParsing() {
        assertThat(SubjectRef.parse("user:acme:ada").id()).isEqualTo("acme:ada");
    }

    @Test
    void parsingAndPrintingRoundTrip() {
        for (String value : new String[]{"user:ada", "group:eng#member", "folder:a/b#viewer"}) {
            assertThat(SubjectRef.parse(value)).hasToString(value);
        }
    }

    @Test
    void malformedSubjectsAreRejected() {
        assertThatThrownBy(() -> SubjectRef.parse("ada")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SubjectRef.parse(":ada")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SubjectRef.parse("user:")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SubjectRef.parse("group:eng#")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SubjectRef.parse("group:#member")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SubjectRef.parse("")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SubjectRef.parse(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aNullRelationIsNormalisedToEmptySoEqualityIsWellDefined() {
        assertThat(new SubjectRef("user", "ada", null)).isEqualTo(SubjectRef.subject("user", "ada"));
    }

    @Test
    void typeAndIdAreRequired() {
        assertThatThrownBy(() -> new SubjectRef("", "ada", "")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SubjectRef("user", " ", "")).isInstanceOf(IllegalArgumentException.class);
    }
}
