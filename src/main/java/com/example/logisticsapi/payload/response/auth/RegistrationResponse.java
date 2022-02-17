package com.example.logisticsapi.payload.response.auth;



import com.example.logisticsapi.model.Staff;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;



@AllArgsConstructor
@Data
@NoArgsConstructor
public class RegistrationResponse {

    private String message;

    private String name;

    private String email;

    private String role ;


    public static RegistrationResponse build(Staff user) {

        return new RegistrationResponse("Registered successfully",
                        user.getName(),
                        user.getEmail(),
                        user.getRole().getName().name());

    }
}
