package com.viniciusdevassis.authentication.sandbox.application.services;

import com.viniciusdevassis.authentication.sandbox.domain.entities.Business;
import com.viniciusdevassis.authentication.sandbox.domain.entities.User;
import com.viniciusdevassis.authentication.sandbox.infrastructure.repositories.BusinessRepository;
import com.viniciusdevassis.authentication.sandbox.infrastructure.repositories.UserRepository;
import com.viniciusdevassis.authentication.sandbox.presentation.dtos.RegisterByGoogleDTO;
import com.viniciusdevassis.authentication.sandbox.presentation.dtos.RegisterByJwtDTO;
import com.viniciusdevassis.authentication.sandbox.presentation.dtos.ResponseUserDTO;
import com.viniciusdevassis.authentication.sandbox.presentation.mappers.BusinessMapper;
import com.viniciusdevassis.authentication.sandbox.presentation.mappers.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Serviço responsável pelas regras de autenticação
 * e criação inicial de usuário + negócio.
 *
 * Camada de aplicação:
 * - Contém regra de negócio
 * - Orquestra persistência
 * - Não contém detalhes de infraestrutura de segurança
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final BusinessRepository businessRepository;
    private final UserMapper userMapper;
    private final BusinessMapper businessMapper;
    private final PasswordEncoder passwordEncoder;

    /**
     * Registro tradicional (email + senha).
     * Senha é obrigatoriamente criptografada antes de persistir.
     */
    @Transactional
    public ResponseUserDTO registerByJWT(RegisterByJwtDTO dto) {

        Business business = saveBusiness(dto.getBusinessName(), dto.getBusinessEmail());

        User user = User.newLocalUser(
                dto.getUsername(),
                dto.getUserEmail(),
                passwordEncoder.encode(dto.getUserPassword())
        );

        user.setBusinessId(business.getId());
        userRepository.save(user);

        return userMapper.userToResponseDTO(user);
    }

    /**
     * Registro via Google.
     * Não há senha local.
     */
    @Transactional
    public ResponseUserDTO registerByGoogle(RegisterByGoogleDTO dto) {

        Business business = saveBusiness(dto.getBusinessName(), dto.getBusinessEmail());

        User user = User.newGoogleUser(
                dto.getUsername(),
                dto.getUserEmail()
        );

        user.setBusinessId(business.getId());
        userRepository.save(user);

        return userMapper.userToResponseDTO(user);
    }

    /**
     * Recupera o ID do usuário autenticado
     * a partir do SecurityContext.
     */
    public UUID getUserIdFromToken() {

        Object principal = SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();

        if (principal instanceof User user) {
            return user.getId();
        }

        throw new IllegalStateException("Invalid authentication principal");
    }

    /**
     * Persiste entidade Business.
     */
    @Transactional
    private Business saveBusiness(String name, String email) {

        Business business = Business.newBusiness(name, email);
        return businessRepository.save(business);
    }
}