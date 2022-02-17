package com.example.logisticsapi.service.serviceImplementation;

import com.example.logisticsapi.dto.UserDto;
import com.example.logisticsapi.exception.ApiBadRequestException;
import com.example.logisticsapi.model.Role;
import com.example.logisticsapi.model.Staff;
import com.example.logisticsapi.payload.request.auth.LoginRequest;
import com.example.logisticsapi.payload.response.auth.JwtRes;
import com.example.logisticsapi.payload.response.auth.RegistrationResponse;
import com.example.logisticsapi.repository.RoleRepository;
import com.example.logisticsapi.repository.StaffRepository;
import com.example.logisticsapi.security.jwt.JwtUtils;
import com.example.logisticsapi.security.service.UserDetailsImpl;
import com.example.logisticsapi.service.AuthService;
import com.example.logisticsapi.util.RoleAssignment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AuthServiceImpl implements AuthService {

    private StaffRepository staffRepository;

    private RoleRepository roleRepository;

    private RoleAssignment roleAssignment;

    private final PasswordEncoder bCryptPasswordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JwtUtils jwtUtils;


    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    public AuthServiceImpl(PasswordEncoder bCryptPasswordEncoder, AuthenticationManager authenticationManager,
                           JwtUtils jwtUtils, RoleAssignment roleAssignment, StaffRepository staffRepository
    , RoleRepository roleRepository) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.roleAssignment = roleAssignment;
        this.staffRepository = staffRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public RegistrationResponse registerUser(UserDto userDto) {
        if (staffRepository.existsByEmail(userDto.getEmail())) {
            throw new ApiBadRequestException("Email already exists, Please try another email");
        }

        String roleString = userDto.getRole();
        Role assignedRole = roleAssignment.assignRole(roleString, roleRepository);

        Staff user = Staff.builder()
                .email(userDto.getEmail())
                .name(userDto.getName())
                .password(bCryptPasswordEncoder.encode(userDto.getPassword()))
                .role(assignedRole)
                        .build();

        saveUser(user);

        return RegistrationResponse.build(user);
    }

    @Override
    public JwtRes authenticateUser(LoginRequest loginReq) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(new
                    UsernamePasswordAuthenticationToken(
                    loginReq.getEmail(),
                    loginReq.getPassword()));

        } catch (BadCredentialsException e) {
            throw new ApiBadRequestException("Incorrect Email or Password");
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return  new JwtRes(jwt,
                userDetails.getId(),
                userDetails.getEmail(),
                roles);
    }

    private void saveUser(Staff user){
        try{
            staffRepository.save(user);
        }catch (Exception e){
            logger.error("Error saving into the User db "+ e.getMessage());
        }
    }
}
