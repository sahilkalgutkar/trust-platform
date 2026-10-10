package com.sahilkalgutkar.trust.identity;

import com.sahilkalgutkar.trust.common.hash.Tokens;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * One credential presented twice at the same moment. Reading the credential and checking that it
 * has not been consumed proves nothing until the consumption commits, and under READ COMMITTED a
 * second request can read it in between, pass the same check, and redeem it again.
 *
 * <p>The first presentation is played by a transaction of the test's own, holding exactly what a
 * redemption writes before it commits: the token it issues, then the consumption. That makes the
 * race deterministic. The second presentation is a real request, which the test lets run until it
 * is waiting on the row the first one holds, and only then commits the first.
 */
class ConcurrentRedemptionIT extends AbstractIdentityIT {

    @Autowired
    private DataSource dataSource;

    @Test
    void aRefreshRacingAnotherRefreshOfTheSameTokenIsTreatedAsAReplay() throws Exception {
        Fixture fixture = provision("race-refresh", true);
        String token = (String) exchangeCode(fixture, authorizeForCode(fixture)).getBody().get("refresh_token");
        String handedToFirst = "handed-to-the-first-refresh";

        ResponseEntity<Map<String, Object>> second;
        try (Connection first = dataSource.getConnection()) {
            first.setAutoCommit(false);
            execute(first, """
                    INSERT INTO refresh_tokens (id, tenant_id, token_hash, family_id, client_id, user_id, scope, expires_at)
                    SELECT gen_random_uuid(), tenant_id, ?, family_id, client_id, user_id, scope, expires_at
                    FROM refresh_tokens WHERE token_hash = ?""", Tokens.hash(handedToFirst), Tokens.hash(token));
            execute(first, "UPDATE refresh_tokens SET consumed_at = now() WHERE token_hash = ?", Tokens.hash(token));

            CompletableFuture<ResponseEntity<Map<String, Object>>> racing =
                    CompletableFuture.supplyAsync(() -> refresh(fixture, token));
            awaitBlockedOnALock(racing);
            first.commit();
            second = racing.get(30, TimeUnit.SECONDS);
        }

        assertThat(second.getStatusCode().value()).isEqualTo(400);
        assertThat(second.getBody()).containsEntry("error", "invalid_grant");
        // Either request could be the thief's, so the token the first one was handed goes too.
        assertThat(liveTokensInTheFamilyOf(handedToFirst)).isZero();
    }

    @Test
    void aCodeExchangeRacingAnotherExchangeOfTheSameCodeIsTreatedAsAReplay() throws Exception {
        Fixture fixture = provision("race-code", true);
        String code = authorizeForCode(fixture);
        String handedToFirst = "handed-to-the-first-exchange";

        ResponseEntity<Map<String, Object>> second;
        try (Connection first = dataSource.getConnection()) {
            first.setAutoCommit(false);
            execute(first, """
                    INSERT INTO refresh_tokens (id, tenant_id, token_hash, family_id, client_id, user_id, scope, expires_at)
                    SELECT gen_random_uuid(), tenant_id, ?, id, client_id, user_id, scope, now() + interval '30 days'
                    FROM authorization_codes WHERE code_hash = ?""", Tokens.hash(handedToFirst), Tokens.hash(code));
            execute(first, "UPDATE authorization_codes SET consumed_at = now() WHERE code_hash = ?", Tokens.hash(code));

            CompletableFuture<ResponseEntity<Map<String, Object>>> racing =
                    CompletableFuture.supplyAsync(() -> exchangeCode(fixture, code));
            awaitBlockedOnALock(racing);
            first.commit();
            second = racing.get(30, TimeUnit.SECONDS);
        }

        assertThat(second.getStatusCode().value()).isEqualTo(400);
        assertThat(second.getBody()).containsEntry("error", "invalid_grant");
        assertThat(liveTokensInTheFamilyOf(handedToFirst)).isZero();
    }

    private static void execute(Connection connection, String sql, String... parameters) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                statement.setString(i + 1, parameters[i]);
            }
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    /**
     * Waits until some session is waiting on a lock, which here can only be the racing request
     * reaching the row the first redemption holds. If it finishes without ever waiting, the
     * assertions on its response say whether that was right.
     */
    private void awaitBlockedOnALock(CompletableFuture<?> racing) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        try (Connection watcher = dataSource.getConnection();
             PreparedStatement waiting = watcher.prepareStatement("""
                     SELECT count(*) FROM pg_stat_activity
                     WHERE datname = current_database() AND wait_event_type = 'Lock'""")) {
            while (!racing.isDone()) {
                try (ResultSet rows = waiting.executeQuery()) {
                    rows.next();
                    if (rows.getInt(1) > 0) {
                        return;
                    }
                }
                if (System.nanoTime() > deadline) {
                    throw new AssertionError("The second request never reached the row the first one holds");
                }
                Thread.sleep(10);
            }
        }
    }

    private long liveTokensInTheFamilyOf(String rawToken) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement live = connection.prepareStatement("""
                     SELECT count(*) FROM refresh_tokens
                     WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = ?)
                       AND consumed_at IS NULL AND revoked_at IS NULL""")) {
            live.setString(1, Tokens.hash(rawToken));
            try (ResultSet rows = live.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }
}
