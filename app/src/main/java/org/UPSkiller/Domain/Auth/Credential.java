package org.UPSkiller.Domain.Auth;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.UPSkiller.Domain.User.User;
import org.hibernate.annotations.Fetch;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name= "credentials")
@Getter
@Setter
@NoArgsConstructor
public class Credential {

    @Id
    @Column(name= "user_id")
    private UUID userId;

    @OneToOne(fetch = FetchType.LAZY)
    @MapsId
    @JoinColumn(name= "user_id")
    private User user;

    @Column(name = "password_hash",nullable = false)
    private String passwordHash;

    @Column(name = "created_at",nullable = false,updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now();
    }
}
