package com.example.logisticsapi.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;


@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class UserDto {

    private String name;

    private String email;

    private String password;

    private String role;


}
