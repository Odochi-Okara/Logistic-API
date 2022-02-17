package com.example.logisticsapi.service;

import com.example.logisticsapi.dto.UserDto;
import com.example.logisticsapi.payload.request.auth.LoginRequest;
import com.example.logisticsapi.payload.response.auth.JwtRes;
import com.example.logisticsapi.payload.response.auth.RegistrationResponse;

public interface AuthService {

     RegistrationResponse registerUser(UserDto userDto);

     JwtRes authenticateUser(LoginRequest loginReq);
}
