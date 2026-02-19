package com.viniciusdevassis.authentication.sandbox.presentation.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class RegisterByGoogleDTO {

    private String businessName;
    private String businessEmail;
    private String username;
    private String userEmail;
}
