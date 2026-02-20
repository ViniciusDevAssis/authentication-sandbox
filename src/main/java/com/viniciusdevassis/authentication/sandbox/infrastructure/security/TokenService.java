package com.viniciusdevassis.authentication.sandbox.infrastructure.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.viniciusdevassis.authentication.sandbox.domain.entities.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * Serviço responsável por:
 *
 * - Gerar tokens JWT após autenticação bem-sucedida.
 * - Validar tokens recebidos nas requisições protegidas.
 *
 * Estratégia adotada:
 *
 * - Algoritmo HMAC256.
 * - Token contém:
 *      → issuer (identifica a aplicação emissora)
 *      → subject (email do usuário)
 *      → expiration (tempo de expiração)
 *
 * - A aplicação é stateless, portanto o JWT
 *   é a única fonte de autenticação.
 */
@Service
public class TokenService {

    /**
     * Identificador da aplicação que emite o token.
     * Utilizado tanto na criação quanto na validação.
     */
    private static final String ISSUER = "authentication-sandbox";

    /**
     * Chave secreta utilizada para assinar o token.
     * Deve estar definida no application.properties.
     */
    @Value("${api.security.token.secret}")
    private String secret;

    /**
     * Gera um JWT para o usuário autenticado.
     *
     * @param user usuário autenticado
     * @return token JWT assinado
     */
    public String generateToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);

            return JWT.create()
                    .withIssuer(ISSUER)                 // identifica quem emitiu o token
                    .withSubject(user.getEmail())       // identifica o usuário (principal)
                    .withExpiresAt(generateExpirationDate()) // define tempo de expiração
                    .sign(algorithm);

        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error while generating token", exception);
        }
    }

    /**
     * Valida o token recebido na requisição.
     *
     * @param token JWT enviado pelo cliente
     * @return subject (email) se válido, ou null se inválido
     */
    public String validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);

            return JWT.require(algorithm)
                    .withIssuer(ISSUER) // garante que o token foi emitido por esta aplicação
                    .build()
                    .verify(token)
                    .getSubject();

        } catch (JWTVerificationException exception) {
            // Token inválido, expirado ou adulterado
            return null;
        }
    }

    /**
     * Define o tempo de expiração do token.
     *
     * Estratégia atual:
     * - 2 horas de validade
     * - Baseado em UTC (evita problemas de fuso horário)
     */
    private Instant generateExpirationDate() {
        return Instant.now().plusSeconds(7200); // 2 horas
    }
}