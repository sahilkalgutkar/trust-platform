package com.sahilkalgutkar.trust.common.hash;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.nio.charset.StandardCharsets;

/**
 * Deterministic JSON serialization, used as the input to the audit hash chain.
 *
 * <p>A hash chain is only tamper-evident if the same logical event always hashes to the same bytes.
 * Jackson's default output does not guarantee that — map iteration order and bean property order
 * can both vary — so verification would fail on untampered records for no reason. This mapper sorts
 * object keys, writes timestamps as ISO-8601 strings instead of floating-point epoch seconds (which
 * lose precision differently across versions), and never pretty-prints.
 */
public final class CanonicalJson {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.INDENT_OUTPUT, false);

    private CanonicalJson() {
    }

    public static byte[] bytes(Object value) {
        return string(value).getBytes(StandardCharsets.UTF_8);
    }

    public static String string(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Value is not canonically serializable: " + value, e);
        }
    }

    public static <T> T parse(String json, Class<T> type) {
        try {
            return MAPPER.readValue(json, type);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Not valid JSON for " + type.getSimpleName(), e);
        }
    }
}
