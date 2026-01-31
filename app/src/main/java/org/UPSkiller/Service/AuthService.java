package org.UPSkiller.Service;

import lombok.RequiredArgsConstructor;
import org.UPSkiller.Domain.Auth.AuthProvider;
import org.UPSkiller.Domain.Auth.Credential;
import org.UPSkiller.Domain.Auth.RefreshToken;
import org.UPSkiller.Domain.User.AccountStatus;
import org.UPSkiller.Domain.User.User;
import org.UPSkiller.Dto.Auth.AuthResponse;
import org.UPSkiller.Dto.Auth.LoginRequest;
import org.UPSkiller.Dto.Auth.SignupRequest;
import org.UPSkiller.Exception.EmailAlreadyExistsException;
import org.UPSkiller.Exception.InvalidCredentials;
import org.UPSkiller.Repository.CredentialRepository;
import org.UPSkiller.Repository.RefreshTokenRepository;
import org.UPSkiller.Repository.UserRepository;
import org.UPSkiller.Util.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;


    @Transactional
    public AuthResponse signup(SignupRequest request) {
        if(userRepository.existsByEmail(request.getEmail())){
            throw new EmailAlreadyExistsException();
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setRole(request.getRole());
        user.setAccountStatus(AccountStatus.ACTIVE);
        user.setAuthProvider(AuthProvider.LOCAL);

        userRepository.save(user);

        Credential credential = new Credential();
        credential.setUser(user);
        credential.setPasswordHash(
                passwordEncoder.encode(request.getPassword())
        );

        credentialRepository.save(credential);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);


        saveRefreshToken(user);
        return new AuthResponse(accessToken, refreshToken);

    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(InvalidCredentials::new);

        Credential credential = credentialRepository.findByUserId(user.getId()).orElseThrow(InvalidCredentials::new);

        if(!passwordEncoder.matches(
                request.getPassword(),
                credential.getPasswordHash()
        )){
            throw new InvalidCredentials();
        }

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        saveRefreshToken(user);

        return new AuthResponse(accessToken,refreshToken);
    }


    public void saveRefreshToken(User user){
        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setUser(user);
        refreshToken.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
        refreshToken.setRevoked(false);
        refreshTokenRepository.save(refreshToken);
    }
}
