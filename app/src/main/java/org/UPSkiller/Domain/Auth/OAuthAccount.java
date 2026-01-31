package org.UPSkiller.Domain.Auth;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.UPSkiller.Domain.User.User;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "oauth_accounts",
        uniqueConstraints = {
          @UniqueConstraint(
                  name = "uq_oauth_user",
                  columnNames = {"provider","provider_user_id"}
          )
        }
)
@Getter
@Setter
@NoArgsConstructor
public class OAuthAccount {
    @Id
    @GeneratedValue
    @Column(name = "id",updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY,optional = false)
    @JoinColumn(name = "user_id",nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider",nullable = false,length = 50)
    private AuthProvider provider;

    @Column(name = "provider_user_id",nullable = false,length = 255)
    private String providerUserId;

    @Column(name = "created_at",nullable = false,updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate(){
        this.createdAt = Instant.now();
    }

}
