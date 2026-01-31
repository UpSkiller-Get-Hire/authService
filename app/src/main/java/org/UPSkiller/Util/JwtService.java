package org.UPSkiller.Util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.UPSkiller.Domain.User.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService {
    private SecretKey secretKey;

    @Value("${security.jwt.secret}")
    private String base64Secret;

    @Value("${security.jwt.access-expiry}")
    private Long accessExpiry;

    @Value("${security.jwt.refresh-expiry}")
    private Long refreshExpiry;

    @PostConstruct
    public void init() {

        if (base64Secret == null || base64Secret.isBlank()) {
            throw new IllegalStateException("JWT secret is missing");
        }
        try {
            byte[] keyBytes = Decoders.BASE64.decode(base64Secret);
            this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid BASE64 JWT secret", e);
        }
    }


    public String generateAccessToken(User user){
        return Jwts.builder()
                .subject(user.getId().toString())
                .claim("role",user.getRole().name())
                .issuer("auth-service")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+accessExpiry))
                .signWith(secretKey)
                .compact();
    }

    public String generateRefreshToken(User user){
        return Jwts.builder()
                .subject(user.getId().toString())
                .issuer("auth-service")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+refreshExpiry))
                .signWith(secretKey)
                .compact();
    }

    public String extractUserId(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public String extractRole(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role").toString();
    }
}
