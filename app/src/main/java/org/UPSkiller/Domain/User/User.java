package org.UPSkiller.Domain.User;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.UPSkiller.Domain.Auth.AuthProvider;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor

public class User {
    @Id
    @GeneratedValue
    @Column(name= "id",updatable = false,nullable = false)
    private UUID id;

    @Column(name= "email",updatable = false,nullable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(name= "role",nullable = false,length = 50)
    private Role role;

    @Enumerated(EnumType.STRING)
    @Column(name= "auth_provider",nullable = false,length = 50)
    private AuthProvider authProvider;

    @Enumerated(EnumType.STRING)
    @Column(name= "account_status",nullable = false,length = 50)
    private AccountStatus accountStatus;

    @Column(name= "created_at",nullable = false,updatable = false)
    private Instant createdAt;

    @Column(name= "updated_at",nullable = false)
    private Instant updatedAt;

    @PrePersist
    protected void onCreate(){
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate(){
        this.updatedAt = Instant.now();
    }
}
