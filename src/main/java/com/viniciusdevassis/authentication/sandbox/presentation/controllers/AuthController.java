package com.viniciusdevassis.authentication.sandbox.presentation.controllers;

import com.viniciusdevassis.authentication.sandbox.application.services.AuthService;
import com.viniciusdevassis.authentication.sandbox.domain.entities.User;
import com.viniciusdevassis.authentication.sandbox.infrastructure.security.TokenService;
import com.viniciusdevassis.authentication.sandbox.presentation.dtos.LoginDTO;
import com.viniciusdevassis.authentication.sandbox.presentation.dtos.RegisterByJwtDTO;
import com.viniciusdevassis.authentication.sandbox.presentation.dtos.ResponseUserDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final AuthService authService;

    /**
     * Registro tradicional (email + senha).
     */
    @PostMapping("/register")
    public ResponseUserDTO register(@RequestBody RegisterByJwtDTO dto) {
        return authService.registerByJWT(dto);
    }

    /**
     * Login tradicional (email + senha).
     * Spring Security valida credenciais.
     * Após autenticação bem-sucedida, geramos JWT.
     */
    @PostMapping("/login")
    public ResponseUserDTO login(@RequestBody LoginDTO dto) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        dto.getEmail(),
                        dto.getPassword()
                )
        );

        User user = (User) authentication.getPrincipal();

        String token = tokenService.generateToken(user);

        return new ResponseUserDTO(user.getUsername(), token);
    }
}