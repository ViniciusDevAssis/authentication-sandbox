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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final BusinessRepository businessRepository;
    private final UserMapper userMapper;
    private final BusinessMapper businessMapper;

    @Transactional
    public ResponseUserDTO registerByJWT(RegisterByJwtDTO dto) {
        Business business = saveBusiness(dto.getBusinessName(), dto.getBusinessEmail());

        User user = User.newUser(
                dto.getUsername(),
                dto.getUserEmail(),
                dto.getUserPassword()
        );
        user.setBusinessId(business.getId());
        userRepository.save(user);
        return userMapper.userToResponseDTO(user);
    }

    @Transactional
    public ResponseUserDTO registerByGoogle(RegisterByGoogleDTO dto) {
        Business business = saveBusiness(dto.getBusinessName(), dto.getBusinessEmail());

        User user = User.newUser(
                dto.getUsername(),
                dto.getUserEmail(),
                "GOOGLE_LOGIN"
        );
        user.setBusinessId(business.getId());
        userRepository.save(user);
        return userMapper.userToResponseDTO(user);
    }

    public

    public UUID getUserIdFromToken() {
        Object principal = SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();
        if (principal instanceof UserDetails) {
            return ((User) principal).getId();
        } else {
            return UUID.fromString(principal.toString());
        }
    }

    @Transactional
    private Business saveBusiness(String name, String email) {
        Business business = Business.newBusiness(name, email);
        businessRepository.save(business);
        return business;
    }
}
