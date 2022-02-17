package com.example.logisticsapi.payload.request.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {
    @NotBlank(message = "Please enter your username")
    private String email;

    @NotBlank(message = "Please enter your password")
    private String password;

}
