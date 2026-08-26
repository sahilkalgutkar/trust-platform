package com.sahilkalgutkar.trust.identity.repo;

import com.sahilkalgutkar.trust.identity.domain.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Note what is missing from every signature here: a tenant argument. Hibernate's tenant
 * discriminator adds it to the generated SQL, so there is no query in this service that can be
 * written without it.
 */
public interface UserRepository extends JpaRepository<UserEntity, UUID> {

    Optional<UserEntity> findByEmail(String email);
}
