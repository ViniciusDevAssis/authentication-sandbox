package com.viniciusdevassis.authentication.sandbox.domain.entities;

import com.viniciusdevassis.authentication.sandbox.domain.enums.AuthProvider;
import com.viniciusdevassis.authentication.sandbox.domain.enums.Role;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Entidade central do sistema representando o usuário.
 *
 * Observações:
 * - Implementa UserDetails para integração com Spring Security.
 * - Suporta múltiplos providers de autenticação (LOCAL, GOOGLE, etc.).
 */
@Entity
@Table(name = "tb_users")
@NoArgsConstructor
@Getter
@Setter(AccessLevel.PRIVATE)
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class User implements UserDetails {

    @Id
    @EqualsAndHashCode.Include
    private UUID id;

    private String name;

    @Column(unique = true, nullable = false)
    private String email;

    /**
     * Armazena senha apenas para usuários LOCAL.
     * Para usuários Google, armazenamos um valor fixo "GOOGLE_LOGIN" ou null.
     */
    private String password;

    /**
     * Define o provedor de autenticação do usuário.
     * Pode ser LOCAL (email+senha) ou GOOGLE (OAuth2).
     */
    @Enumerated(EnumType.STRING)
    private AuthProvider provider;

    /**
     * Define o role do usuário.
     */
    @Setter
    @Enumerated(EnumType.STRING)
    private Role role;

    /**
     * Cria um novo usuário LOCAL.
     */
    public static User newLocalUser(String name, String email, String password) {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setName(name);
        user.setEmail(email);
        user.setPassword(password);
        user.setProvider(AuthProvider.LOCAL);
        return user;
    }

    /**
     * Cria um novo usuário Google.
     */
    public static User newGoogleUser(String name, String email) {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setName(name);
        user.setEmail(email);
        user.setPassword(null);
        user.setProvider(AuthProvider.GOOGLE);
        return user;
    }

    /* --------------------- Métodos UserDetails --------------------- */

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (role == null) {
            return List.of();
        }
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Por enquanto, não implementamos expiração de conta
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Por enquanto, não implementamos bloqueio
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Por enquanto, credenciais nunca expiram
    }

    @Override
    public boolean isEnabled() {
        return true; // Por enquanto, todos os usuários estão ativos
    }
}