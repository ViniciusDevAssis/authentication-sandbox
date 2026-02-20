package com.viniciusdevassis.authentication.sandbox.infrastructure.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.viniciusdevassis.authentication.sandbox.domain.entities.User;
import com.viniciusdevassis.authentication.sandbox.domain.enums.AuthProvider;
import com.viniciusdevassis.authentication.sandbox.infrastructure.repositories.UserRepository;
import com.viniciusdevassis.authentication.sandbox.presentation.dtos.ResponseUserDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * Classe central de configuração de segurança da aplicação.
 *
 * Estratégia adotada:
 *
 * - API totalmente stateless (sem uso de sessão HTTP).
 * - JWT como mecanismo principal de autenticação.
 * - OAuth2 (Google) utilizado apenas como provedor de identidade.
 * - Após autenticação OAuth2 bem-sucedida:
 *      → Criamos ou validamos o usuário.
 *      → Geramos um JWT.
 *      → Retornamos resposta JSON (REST puro).
 *
 * Fluxos suportados:
 *
 * 1) Login/Cadastro LOCAL (email + senha)
 * 2) Login via Google (OAuth2)
 *
 * Após autenticação, todos os acessos são protegidos via JWT.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final SecurityFilter securityFilter;
    private final UserRepository userRepository;
    private final TokenService tokenService;

    /**
     * Define a cadeia principal de filtros de segurança.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http

                /*
                 * Desabilita CSRF porque:
                 * - A aplicação é stateless
                 * - Não utilizamos sessão baseada em cookies
                 */
                .csrf(csrf -> csrf.disable())

                /*
                 * Configuração de CORS para permitir
                 * comunicação com o frontend (Nesse caso, Next.js).
                 */
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                /*
                 * Define política de sessão como STATELESS.
                 * O Spring não criará nem utilizará HttpSession.
                 */
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                /*
                 * Regras de autorização:
                 *
                 * - /auth/** → endpoints de login/cadastro LOCAL
                 * - /oauth2/** e /login/** → fluxo OAuth2
                 * - Demais endpoints exigem autenticação via JWT
                 */
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/auth/**").permitAll()
                        .requestMatchers("/oauth2/**", "/login/**").permitAll()
                        .anyRequest().authenticated()
                )

                /*
                 * Configuração de login com Google (OAuth2).
                 *
                 * Ao autenticar com sucesso:
                 * - Extraímos email e nome do provedor.
                 * - Validamos regras de provider.
                 * - Criamos usuário se necessário.
                 * - Geramos JWT.
                 * - Retornamos JSON (REST puro).
                 */
                .oauth2Login(oauth2 -> oauth2
                        .successHandler((request, response, authentication) -> {

                            var principal =
                                    (org.springframework.security.oauth2.core.user.OAuth2User)
                                            authentication.getPrincipal();

                            String email = principal.getAttribute("email");
                            String name = principal.getAttribute("name");

                            /*
                             * Regras de consistência:
                             *
                             * - Se já existir usuário LOCAL com esse email → bloquear.
                             * - Se já existir usuário GOOGLE → utilizar.
                             * - Se não existir → criar novo usuário GOOGLE.
                             */
                            User user = userRepository.findByEmail(email)
                                    .map(existingUser -> {
                                        if (existingUser.getProvider() != AuthProvider.GOOGLE) {
                                            throw new RuntimeException(
                                                    "Email already registered with local account."
                                            );
                                        }
                                        return existingUser;
                                    })
                                    .orElseGet(() ->
                                            userRepository.save(
                                                    User.newGoogleUser(name, email)
                                            )
                                    );

                            // Geração do token JWT
                            String token = tokenService.generateToken(user);

                            /*
                             * Resposta REST pura:
                             * - Status 200
                             * - Content-Type JSON
                             * - Corpo com nome + token
                             */
                            response.setContentType("application/json");
                            response.setStatus(HttpServletResponse.SC_OK);

                            new ObjectMapper().writeValue(
                                    response.getWriter(),
                                    new ResponseUserDTO(name, token)
                            );
                        })
                )

                /*
                 * Adiciona filtro JWT antes do filtro padrão
                 * de autenticação do Spring.
                 */
                .addFilterBefore(
                        securityFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }

    /**
     * Configuração de CORS.
     *
     * Permite requisições do frontend Next.js
     * rodando em http://localhost:3000.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of("http://localhost:3000"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", config);

        return source;
    }

    /**
     * Encoder utilizado para criptografia
     * de senhas de contas LOCAL.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Exposição do AuthenticationManager.
     *
     * Necessário para login tradicional
     * (email + senha) via AuthController.
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration
    ) throws Exception {
        return configuration.getAuthenticationManager();
    }
}