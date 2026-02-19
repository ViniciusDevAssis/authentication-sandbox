package com.viniciusdevassis.authentication.sandbox.infrastructure.security;

import com.viniciusdevassis.authentication.sandbox.domain.entities.User;
import com.viniciusdevassis.authentication.sandbox.infrastructure.repositories.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro responsável por interceptar todas as requisições HTTP
 * e validar o token JWT enviado no header Authorization.
 *
 * Ele executa antes dos controllers e define o usuário autenticado
 * no SecurityContext caso o token seja válido.
 *
 * Essa classe é executada uma única vez por requisição
 * (por herdar de OncePerRequestFilter).
 */
@Component
@RequiredArgsConstructor
public class SecurityFilter extends OncePerRequestFilter {

    /**
     * Serviço responsável por validar e extrair informações do JWT.
     */
    private final TokenService tokenService;

    /**
     * Repositório usado para carregar o usuário a partir do email
     * extraído do token.
     */
    private final UserRepository userRepository;

    /**
     * Método principal executado para cada requisição HTTP.
     *
     * Fluxo:
     * 1 - Recupera o token do header Authorization.
     * 2 - Valida o token.
     * 3 - Se válido, carrega o usuário do banco.
     * 4 - Cria um objeto Authentication autenticado.
     * 5 - Define o usuário no SecurityContext.
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Recupera o token do header
        String token = recoverToken(request);

        // Se não houver token, apenas continua a requisição
        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Valida o token e extrai o login (email)
        String login = tokenService.validateToken(token);

        // Se o token for inválido, continua sem autenticar
        if (login == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Evita sobrescrever autenticação já existente
        if (SecurityContextHolder.getContext().getAuthentication() == null) {

            User user = userRepository.findByEmail(login)
                    .orElseThrow(() ->
                            new UsernameNotFoundException("User not found for validated token")
                    );

            /*
             * Criamos um Authentication autenticado.
             *
             * - Principal: objeto User (deve implementar UserDetails)
             * - Credentials: null (não precisamos da senha aqui)
             * - Authorities: permissões do usuário
             */
            var authentication = new UsernamePasswordAuthenticationToken(
                    user,
                    null,
                    user.getAuthorities()
            );

            // Define o usuário autenticado no contexto da aplicação
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        // Continua o fluxo normal da requisição
        filterChain.doFilter(request, response);
    }

    /**
     * Recupera o token JWT do header Authorization.
     *
     * Formato esperado:
     * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
     */
    private String recoverToken(HttpServletRequest request) {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }
}
