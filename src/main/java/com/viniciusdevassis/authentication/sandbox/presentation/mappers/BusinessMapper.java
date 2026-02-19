package com.viniciusdevassis.authentication.sandbox.presentation.mappers;

import com.viniciusdevassis.authentication.sandbox.domain.entities.Business;
import com.viniciusdevassis.authentication.sandbox.presentation.dtos.ResponseBusinessDTO;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface BusinessMapper {

    ResponseBusinessDTO businessToResponseBusinessDTO(Business business);

    Business responseBusinessDTOToBusiness(ResponseBusinessDTO dto);
}
