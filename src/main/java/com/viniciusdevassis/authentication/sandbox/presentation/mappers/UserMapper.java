package com.viniciusdevassis.authentication.sandbox.presentation.mappers;

import com.viniciusdevassis.authentication.sandbox.domain.entities.User;
import com.viniciusdevassis.authentication.sandbox.presentation.dtos.ResponseUserDTO;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    ResponseUserDTO userToResponseDTO(User user);

    User responseUserDTOToUser(ResponseUserDTO dto);
}
