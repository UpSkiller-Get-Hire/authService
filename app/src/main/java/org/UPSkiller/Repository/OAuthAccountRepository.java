package org.UPSkiller.Repository;

import org.UPSkiller.Domain.Auth.AuthProvider;
import org.UPSkiller.Domain.Auth.OAuthAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface OAuthAccountRepository extends JpaRepository<OAuthAccount, UUID> {
    Optional<OAuthAccount> findByProviderAndProviderUserId(
            AuthProvider provider,
            String providerUserId
    );
}
