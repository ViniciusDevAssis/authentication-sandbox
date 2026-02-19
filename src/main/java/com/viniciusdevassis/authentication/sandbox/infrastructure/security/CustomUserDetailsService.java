package com.viniciusdevassis.authentication.sandbox.infrastructure.security;

import com.viniciusdevassis.authentication.sandbox.domain.entities.User;
import com.viniciusdevassis.authentication.sandbox.infrastructure.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Implementação do UserDetailsService do Spring Security.
 *
 * RESPONSABILIDADE:
 * Essa classe é utilizada pelo AuthenticationManager durante o processo
 * de autenticação tradicional (email + senha).
 *
 * Quando o usuário tenta fazer login, o Spring chama automaticamente
 * o método loadUserByUsername, passando o "username".
 *
 * Neste sistema, estamos utilizando o EMAIL como username.
 *
 * IMPORTANTE:
 * - Estamos retornando diretamente nossa entidade User.
 * - Isso é possível porque User implementa UserDetails.
 * - Dessa forma mantemos consistência: o principal do SecurityContext
 *   será sempre a entidade User.
 *
 * Se no futuro quisermos desacoplar domínio de segurança,
 * o ideal seria criar um Adapter (SecurityUser).
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    /**
     * Repositório responsável por buscar usuários no banco.
     */
    private final UserRepository repository;

    /**
     * Método chamado automaticamente pelo Spring Security
     * durante o processo de autenticação.
     *
     * @param username Neste projeto representa o email do usuário.
     * @return UserDetails que será usado pelo Spring para validar a senha.
     * @throws UsernameNotFoundException caso o email não exista.
     *
     * Fluxo interno:
     * 1. O AuthenticationManager recebe email e senha.
     * 2. Ele chama este método passando o email.
     * 3. Aqui buscamos o usuário no banco.
     * 4. Se encontrado, retornamos a entidade.
     * 5. O Spring então compara a senha informada com a senha armazenada
     *    usando o PasswordEncoder configurado.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        return repository.findByEmail(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found")
                );
    }
}
