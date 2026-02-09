package org.UPSkiller.Util;

import com.nimbusds.jose.crypto.impl.RSAKeyUtils;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.UPSkiller.Domain.User.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;


import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private PublicKey publicKey;
    private PrivateKey  privateKey;

    @Value("${security.jwt.access-expiry}")
    private Long accessExpiry;

    @Value("${security.jwt.refresh-expiry}")
    private Long refreshExpiry;

    private final RsaKeyLoader rsaKeyLoader;

    @PostConstruct
    public void init() {

        try {
            this.privateKey = rsaKeyLoader.loadPrivateKey();
            this.publicKey = rsaKeyLoader.loadPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA keys", e);
        }
    }


    public String generateAccessToken(User user){
        return Jwts.builder()
                .subject(user.getId().toString())
                .claim("role",user.getRole().name())
                .issuer("auth-service")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+accessExpiry))
                .signWith(privateKey,Jwts.SIG.RS256)
                .compact();
    }

    public String generateRefreshToken(User user, UUID refreshTokenId){
        return Jwts.builder()
                .subject(user.getId().toString())
                .id(refreshTokenId.toString())
                .issuer("auth-service")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+refreshExpiry))
                .signWith(privateKey,Jwts.SIG.RS256)
                .compact();
    }

    public String extractUserId(String token){
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public String extractRole(String token){
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role").toString();
    }
}
