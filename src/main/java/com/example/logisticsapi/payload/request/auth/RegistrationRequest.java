package com.example.logisticsapi.payload.request.auth;

import com.example.logisticsapi.validation.annotations.ValidEmail;
import com.example.logisticsapi.validation.annotations.ValidPassword;
import lombok.*;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class RegistrationRequest implements Serializable {


    @NotNull(message = "Name cannot be null")
    @NotBlank(message = "Name cannot be empty")
    private String name;

    @NotNull(message = "Email entered is not valid")
    @Email(message = "This must be a valid email")
    @Size(max = 50, message = "Email should contain characters not more than 50")
    @NotBlank(message = "Email field cannot be blank")
    @ValidEmail(message = "Email is not valid")
    private String email;

    @NotNull(message = "Password field cannot be null")
    @NotBlank(message = "Password field cannot be null")
    @Size(min = 8, max= 20, message = "Password should be 8 characters or more")
    @ValidPassword(message = "Password should be 8 characters or more and valid")
    private String password;



}
