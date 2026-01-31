package org.UPSkiller.Repository;

import org.UPSkiller.Domain.Auth.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByIdAndRevokedFalse(UUID id);

    List<RefreshToken> findAllByUser_Id(UUID userId);

    void deleteAllByUser_Id(UUID userId);

    void deleteAllByExpiresAtBefore(Instant now);
}
