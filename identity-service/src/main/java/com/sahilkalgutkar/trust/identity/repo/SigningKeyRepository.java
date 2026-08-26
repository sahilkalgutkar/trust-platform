package com.sahilkalgutkar.trust.identity.repo;

import com.sahilkalgutkar.trust.identity.domain.SigningKeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SigningKeyRepository extends JpaRepository<SigningKeyEntity, String> {

    Optional<SigningKeyEntity> findFirstByStatus(String status);

    List<SigningKeyEntity> findAllByOrderByCreatedAtDesc();
}
