package org.UPSkiller.Service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.UPSkiller.Domain.Auth.AuthProvider;
import org.UPSkiller.Domain.Auth.Credential;
import org.UPSkiller.Domain.Auth.RefreshToken;
import org.UPSkiller.Domain.User.AccountStatus;
import org.UPSkiller.Domain.User.User;
import org.UPSkiller.Dto.Auth.LoginRequest;
import org.UPSkiller.Dto.Auth.SignupRequest;
import org.UPSkiller.Exception.EmailAlreadyExistsException;
import org.UPSkiller.Exception.InvalidCredentials;
import org.UPSkiller.Repository.CredentialRepository;
import org.UPSkiller.Repository.RefreshTokenRepository;
import org.UPSkiller.Repository.UserRepository;
import org.UPSkiller.Util.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${security.jwt.access-expiry}")
    private Long accessExpiry;

    @Value("${security.jwt.refresh-expiry}")
    private Long refreshExpiry;

    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;


    @Transactional
    public void signup(SignupRequest request,HttpServletResponse response) {
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
        RefreshToken dbToken = saveRefreshToken(user);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user,dbToken.getId());


        saveRefreshToken(user);

        addCookie(response,"accessToken",accessToken,(int) (accessExpiry / 1000),"/");

        addCookie(response, "refreshToken", refreshToken, (int) (refreshExpiry / 1000), "/auth/refresh");


    }

    public void login(LoginRequest request,HttpServletResponse response) {
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(InvalidCredentials::new);

        Credential credential = credentialRepository.findByUserId(user.getId()).orElseThrow(InvalidCredentials::new);

        if(!passwordEncoder.matches(
                request.getPassword(),
                credential.getPasswordHash()
        )){
            throw new InvalidCredentials();
        }

        credentialRepository.save(credential);
        RefreshToken dbToken = saveRefreshToken(user);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, dbToken.getId());

        saveRefreshToken(user);

        addCookie(response,
                "accessToken",
                accessToken,
                (int) (accessExpiry / 1000),
                "/"
        );

        addCookie(response,
                "refreshToken",
                refreshToken,
                (int) (refreshExpiry / 1000),
                "/auth/refresh"
        );

    }


    public RefreshToken saveRefreshToken(User user){
        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setUser(user);
        refreshToken.setExpiresAt(Instant.now().plus(refreshExpiry, ChronoUnit.MILLIS));
        refreshToken.setRevoked(false);
        return refreshTokenRepository.save(refreshToken);
    }
    private void addCookie(
            HttpServletResponse response,
            String name,
            String value,
            int maxAgeSeconds,
            String path
    ){
        Cookie cookie = new Cookie(name,value);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // for local dev
        cookie.setPath(path);
        cookie.setMaxAge(maxAgeSeconds);
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
    }
}
