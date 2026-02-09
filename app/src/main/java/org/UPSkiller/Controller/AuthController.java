package org.UPSkiller.Controller;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.UPSkiller.Dto.Auth.LoginRequest;
import org.UPSkiller.Dto.Auth.SignupRequest;
import org.UPSkiller.Service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<Map<String,String>> signup(@Valid @RequestBody SignupRequest signupRequest, HttpServletResponse response) {
        authService.signup(signupRequest,response);
        return ResponseEntity.ok(Map.of("message","Signup successful"));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String,String>> login (@Valid @RequestBody LoginRequest loginRequest,HttpServletResponse response) {
        authService.login(loginRequest,response);
        return ResponseEntity.ok(Map.of("message","Login successful"));
    }
}
