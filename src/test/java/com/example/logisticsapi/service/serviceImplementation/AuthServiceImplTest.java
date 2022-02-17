package com.example.logisticsapi.service.serviceImplementation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.logisticsapi.dto.UserDto;
import com.example.logisticsapi.exception.ApiBadRequestException;
import com.example.logisticsapi.model.Role;
import com.example.logisticsapi.model.Staff;
import com.example.logisticsapi.model.enums.ERole;
import com.example.logisticsapi.payload.request.auth.LoginRequest;
import com.example.logisticsapi.payload.response.auth.JwtRes;
import com.example.logisticsapi.payload.response.auth.RegistrationResponse;
import com.example.logisticsapi.repository.RoleRepository;
import com.example.logisticsapi.repository.StaffRepository;
import com.example.logisticsapi.security.jwt.JwtUtils;
import com.example.logisticsapi.security.service.UserDetailsImpl;
import com.example.logisticsapi.util.RoleAssignment;

import java.time.LocalDateTime;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ContextConfiguration(classes = {AuthServiceImpl.class})
@ExtendWith(SpringExtension.class)
class AuthServiceImplTest {
    @Autowired
    private AuthServiceImpl authServiceImpl;

    @MockBean
    private AuthenticationManager authenticationManager;

    @MockBean
    private JwtUtils jwtUtils;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @MockBean
    private RoleAssignment roleAssignment;

    @MockBean
    private RoleRepository roleRepository;

    @MockBean
    private StaffRepository staffRepository;

    @Test
    void testRegisterUser() {
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(true);
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role")));
        verify(this.staffRepository).existsByEmail((String) any());
    }

    @Test
    void testRegisterUser2() {
        when(this.staffRepository.existsByEmail((String) any())).thenThrow(new ApiBadRequestException("An error occurred"));
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role")));
        verify(this.staffRepository).existsByEmail((String) any());
    }

    @Test
    void testRegisterUser3() {
        Role role = new Role();
        role.setId(123L);
        role.setName(ERole.ROLE_STAFF);

        Staff staff = new Staff();
        staff.setCreatedAt(LocalDateTime.of(1, 1, 1, 1, 1));
        staff.setEmail("jane.doe@example.org");
        staff.setId(123L);
        staff.setName("Name");
        staff.setPassword("iloveyou");
        staff.setRole(role);
        staff.setUpdatedAt(LocalDateTime.of(1, 1, 1, 1, 1));
        when(this.staffRepository.save((Staff) any())).thenReturn(staff);
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(false);

        Role role1 = new Role();
        role1.setId(123L);
        role1.setName(ERole.ROLE_STAFF);
        when(this.roleAssignment.assignRole((String) any(), (RoleRepository) any())).thenReturn(role1);
        when(this.passwordEncoder.encode((CharSequence) any())).thenReturn("secret");
        RegistrationResponse actualRegisterUserResult = this.authServiceImpl
                .registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role"));
        assertEquals("jane.doe@example.org", actualRegisterUserResult.getEmail());
        assertEquals("ROLE_STAFF", actualRegisterUserResult.getRole());
        assertEquals("Name", actualRegisterUserResult.getName());
        assertEquals("Registered successfully", actualRegisterUserResult.getMessage());
        verify(this.staffRepository).existsByEmail((String) any());
        verify(this.staffRepository).save((Staff) any());
        verify(this.roleAssignment).assignRole((String) any(), (RoleRepository) any());
        verify(this.passwordEncoder).encode((CharSequence) any());
    }

    @Test
    void testRegisterUser4() {
        when(this.staffRepository.save((Staff) any())).thenThrow(new ApiBadRequestException("An error occurred"));
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(false);

        Role role = new Role();
        role.setId(123L);
        role.setName(ERole.ROLE_STAFF);
        when(this.roleAssignment.assignRole((String) any(), (RoleRepository) any())).thenReturn(role);
        when(this.passwordEncoder.encode((CharSequence) any())).thenReturn("secret");
        RegistrationResponse actualRegisterUserResult = this.authServiceImpl
                .registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role"));
        assertEquals("jane.doe@example.org", actualRegisterUserResult.getEmail());
        assertEquals("ROLE_STAFF", actualRegisterUserResult.getRole());
        assertEquals("Name", actualRegisterUserResult.getName());
        assertEquals("Registered successfully", actualRegisterUserResult.getMessage());
        verify(this.staffRepository).existsByEmail((String) any());
        verify(this.staffRepository).save((Staff) any());
        verify(this.roleAssignment).assignRole((String) any(), (RoleRepository) any());
        verify(this.passwordEncoder).encode((CharSequence) any());
    }

    @Test
    void testRegisterUser5() {
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(true);
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role")));
        verify(this.staffRepository).existsByEmail((String) any());
    }

    @Test
    void testRegisterUser6() {
        when(this.staffRepository.existsByEmail((String) any())).thenThrow(new ApiBadRequestException("An error occurred"));
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role")));
        verify(this.staffRepository).existsByEmail((String) any());
    }

    @Test
    void testRegisterUser7() {
        Role role = new Role();
        role.setId(123L);
        role.setName(ERole.ROLE_STAFF);

        Staff staff = new Staff();
        staff.setCreatedAt(LocalDateTime.of(1, 1, 1, 1, 1));
        staff.setEmail("jane.doe@example.org");
        staff.setId(123L);
        staff.setName("Name");
        staff.setPassword("iloveyou");
        staff.setRole(role);
        staff.setUpdatedAt(LocalDateTime.of(1, 1, 1, 1, 1));
        when(this.staffRepository.save((Staff) any())).thenReturn(staff);
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(false);

        Role role1 = new Role();
        role1.setId(123L);
        role1.setName(ERole.ROLE_STAFF);
        when(this.roleAssignment.assignRole((String) any(), (RoleRepository) any())).thenReturn(role1);
        when(this.passwordEncoder.encode((CharSequence) any())).thenReturn("secret");
        RegistrationResponse actualRegisterUserResult = this.authServiceImpl
                .registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role"));
        assertEquals("jane.doe@example.org", actualRegisterUserResult.getEmail());
        assertEquals("ROLE_STAFF", actualRegisterUserResult.getRole());
        assertEquals("Name", actualRegisterUserResult.getName());
        assertEquals("Registered successfully", actualRegisterUserResult.getMessage());
        verify(this.staffRepository).existsByEmail((String) any());
        verify(this.staffRepository).save((Staff) any());
        verify(this.roleAssignment).assignRole((String) any(), (RoleRepository) any());
        verify(this.passwordEncoder).encode((CharSequence) any());
    }

    @Test
    void testRegisterUser8() {
        when(this.staffRepository.save((Staff) any())).thenThrow(new ApiBadRequestException("An error occurred"));
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(false);

        Role role = new Role();
        role.setId(123L);
        role.setName(ERole.ROLE_STAFF);
        when(this.roleAssignment.assignRole((String) any(), (RoleRepository) any())).thenReturn(role);
        when(this.passwordEncoder.encode((CharSequence) any())).thenReturn("secret");
        RegistrationResponse actualRegisterUserResult = this.authServiceImpl
                .registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role"));
        assertEquals("jane.doe@example.org", actualRegisterUserResult.getEmail());
        assertEquals("ROLE_STAFF", actualRegisterUserResult.getRole());
        assertEquals("Name", actualRegisterUserResult.getName());
        assertEquals("Registered successfully", actualRegisterUserResult.getMessage());
        verify(this.staffRepository).existsByEmail((String) any());
        verify(this.staffRepository).save((Staff) any());
        verify(this.roleAssignment).assignRole((String) any(), (RoleRepository) any());
        verify(this.passwordEncoder).encode((CharSequence) any());
    }

    @Test
    void testRegisterUser9() {
        Role role = new Role();
        role.setId(123L);
        role.setName(ERole.ROLE_STAFF);

        Staff staff = new Staff();
        staff.setCreatedAt(LocalDateTime.of(1, 1, 1, 1, 1));
        staff.setEmail("jane.doe@example.org");
        staff.setId(123L);
        staff.setName("Name");
        staff.setPassword("iloveyou");
        staff.setRole(role);
        staff.setUpdatedAt(LocalDateTime.of(1, 1, 1, 1, 1));
        when(this.staffRepository.save((Staff) any())).thenReturn(staff);
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(false);

        Role role1 = new Role();
        role1.setId(123L);
        role1.setName(ERole.ROLE_STAFF);
        when(this.roleAssignment.assignRole((String) any(), (RoleRepository) any())).thenReturn(role1);
        when(this.passwordEncoder.encode((CharSequence) any())).thenReturn("secret");
        UserDto userDto = mock(UserDto.class);
        when(userDto.getPassword()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(userDto.getName()).thenReturn("Name");
        when(userDto.getRole()).thenReturn("Role");
        when(userDto.getEmail()).thenReturn("jane.doe@example.org");
        assertThrows(ApiBadRequestException.class, () -> this.authServiceImpl.registerUser(userDto));
        verify(this.staffRepository).existsByEmail((String) any());
        verify(this.roleAssignment).assignRole((String) any(), (RoleRepository) any());
        verify(userDto, atLeast(1)).getEmail();
        verify(userDto).getName();
        verify(userDto).getPassword();
        verify(userDto).getRole();
    }

    @Test
    void testRegisterUser10() {
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(true);
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role")));
        verify(this.staffRepository).existsByEmail((String) any());
    }

    @Test
    void testRegisterUser11() {
        when(this.staffRepository.existsByEmail((String) any())).thenThrow(new ApiBadRequestException("An error occurred"));
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role")));
        verify(this.staffRepository).existsByEmail((String) any());
    }

    @Test
    void testRegisterUser12() {
        Role role = new Role();
        role.setId(123L);
        role.setName(ERole.ROLE_STAFF);

        Staff staff = new Staff();
        staff.setCreatedAt(LocalDateTime.of(1, 1, 1, 1, 1));
        staff.setEmail("jane.doe@example.org");
        staff.setId(123L);
        staff.setName("Name");
        staff.setPassword("iloveyou");
        staff.setRole(role);
        staff.setUpdatedAt(LocalDateTime.of(1, 1, 1, 1, 1));
        when(this.staffRepository.save((Staff) any())).thenReturn(staff);
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(false);

        Role role1 = new Role();
        role1.setId(123L);
        role1.setName(ERole.ROLE_STAFF);
        when(this.roleAssignment.assignRole((String) any(), (RoleRepository) any())).thenReturn(role1);
        when(this.passwordEncoder.encode((CharSequence) any())).thenReturn("secret");
        RegistrationResponse actualRegisterUserResult = this.authServiceImpl
                .registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role"));
        assertEquals("jane.doe@example.org", actualRegisterUserResult.getEmail());
        assertEquals("ROLE_STAFF", actualRegisterUserResult.getRole());
        assertEquals("Name", actualRegisterUserResult.getName());
        assertEquals("Registered successfully", actualRegisterUserResult.getMessage());
        verify(this.staffRepository).existsByEmail((String) any());
        verify(this.staffRepository).save((Staff) any());
        verify(this.roleAssignment).assignRole((String) any(), (RoleRepository) any());
        verify(this.passwordEncoder).encode((CharSequence) any());
    }

    @Test
    void testRegisterUser13() {
        when(this.staffRepository.save((Staff) any())).thenThrow(new ApiBadRequestException("An error occurred"));
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(false);

        Role role = new Role();
        role.setId(123L);
        role.setName(ERole.ROLE_STAFF);
        when(this.roleAssignment.assignRole((String) any(), (RoleRepository) any())).thenReturn(role);
        when(this.passwordEncoder.encode((CharSequence) any())).thenReturn("secret");
        RegistrationResponse actualRegisterUserResult = this.authServiceImpl
                .registerUser(new UserDto("Name", "jane.doe@example.org", "iloveyou", "Role"));
        assertEquals("jane.doe@example.org", actualRegisterUserResult.getEmail());
        assertEquals("ROLE_STAFF", actualRegisterUserResult.getRole());
        assertEquals("Name", actualRegisterUserResult.getName());
        assertEquals("Registered successfully", actualRegisterUserResult.getMessage());
        verify(this.staffRepository).existsByEmail((String) any());
        verify(this.staffRepository).save((Staff) any());
        verify(this.roleAssignment).assignRole((String) any(), (RoleRepository) any());
        verify(this.passwordEncoder).encode((CharSequence) any());
    }

    @Test
    void testRegisterUser14() {
        Role role = new Role();
        role.setId(123L);
        role.setName(ERole.ROLE_STAFF);

        Staff staff = new Staff();
        staff.setCreatedAt(LocalDateTime.of(1, 1, 1, 1, 1));
        staff.setEmail("jane.doe@example.org");
        staff.setId(123L);
        staff.setName("Name");
        staff.setPassword("iloveyou");
        staff.setRole(role);
        staff.setUpdatedAt(LocalDateTime.of(1, 1, 1, 1, 1));
        when(this.staffRepository.save((Staff) any())).thenReturn(staff);
        when(this.staffRepository.existsByEmail((String) any())).thenReturn(false);

        Role role1 = new Role();
        role1.setId(123L);
        role1.setName(ERole.ROLE_STAFF);
        when(this.roleAssignment.assignRole((String) any(), (RoleRepository) any())).thenReturn(role1);
        when(this.passwordEncoder.encode((CharSequence) any())).thenReturn("secret");
        UserDto userDto = mock(UserDto.class);
        when(userDto.getPassword()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(userDto.getName()).thenReturn("Name");
        when(userDto.getRole()).thenReturn("Role");
        when(userDto.getEmail()).thenReturn("jane.doe@example.org");
        assertThrows(ApiBadRequestException.class, () -> this.authServiceImpl.registerUser(userDto));
        verify(this.staffRepository).existsByEmail((String) any());
        verify(this.roleAssignment).assignRole((String) any(), (RoleRepository) any());
        verify(userDto, atLeast(1)).getEmail();
        verify(userDto).getName();
        verify(userDto).getPassword();
        verify(userDto).getRole();
    }

    @Test
    void testAuthenticateUser() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any()))
                .thenThrow(new ApiBadRequestException("An error occurred"));
        when(this.authenticationManager.authenticate((Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou")));
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
    }

    @Test
    void testAuthenticateUser2() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any())).thenReturn("ABC123");
        ArrayList<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
        when(this.authenticationManager.authenticate((Authentication) any())).thenReturn(new TestingAuthenticationToken(
                new UserDetailsImpl(123L, "jane.doe@example.org", "iloveyou", grantedAuthorityList), "Credentials"));
        JwtRes actualAuthenticateUserResult = this.authServiceImpl
                .authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou"));
        assertEquals("ABC123", actualAuthenticateUserResult.getAccessToken());
        assertEquals("Bearer", actualAuthenticateUserResult.getTokenType());
        assertEquals(grantedAuthorityList, actualAuthenticateUserResult.getRoles());
        assertEquals(123L, actualAuthenticateUserResult.getId().longValue());
        assertEquals("jane.doe@example.org", actualAuthenticateUserResult.getEmail());
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
    }

    @Test
    void testAuthenticateUser3() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any())).thenReturn("ABC123");
        UserDetailsImpl userDetailsImpl = mock(UserDetailsImpl.class);
        when(userDetailsImpl.getEmail()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(userDetailsImpl.getId()).thenReturn(123L);
        when(userDetailsImpl.getAuthorities()).thenReturn(new ArrayList<>());
        TestingAuthenticationToken testingAuthenticationToken = new TestingAuthenticationToken(userDetailsImpl,
                "Credentials");

        when(this.authenticationManager.authenticate((Authentication) any())).thenReturn(testingAuthenticationToken);
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou")));
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
        verify(userDetailsImpl).getAuthorities();
        verify(userDetailsImpl).getEmail();
        verify(userDetailsImpl).getId();
    }

    @Test
    void testAuthenticateUser4() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any())).thenReturn("ABC123");
        UserDetailsImpl userDetailsImpl = mock(UserDetailsImpl.class);
        when(userDetailsImpl.getId()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(userDetailsImpl.getAuthorities()).thenReturn(new ArrayList<>());
        TestingAuthenticationToken testingAuthenticationToken = new TestingAuthenticationToken(userDetailsImpl,
                "Credentials", new ArrayList<>());

        when(this.authenticationManager.authenticate((Authentication) any())).thenReturn(testingAuthenticationToken);
        new ApiBadRequestException("An error occurred");
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou")));
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
        verify(userDetailsImpl).getAuthorities();
        verify(userDetailsImpl).getId();
    }

    @Test
    void testAuthenticateUser5() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((org.springframework.security.core.Authentication) any())).thenReturn("ABC123");
        when(this.authenticationManager.authenticate((org.springframework.security.core.Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        new ApiBadRequestException("An error occurred");
        new ApiBadRequestException("An error occurred");
        LoginRequest loginRequest = mock(LoginRequest.class);
        when(loginRequest.getPassword()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(loginRequest.getEmail()).thenReturn("jane.doe@example.org");
        assertThrows(ApiBadRequestException.class, () -> this.authServiceImpl.authenticateUser(loginRequest));
        verify(loginRequest).getEmail();
        verify(loginRequest).getPassword();
    }

    @Test
    void testAuthenticateUser6() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((org.springframework.security.core.Authentication) any())).thenReturn("ABC123");
        when(this.authenticationManager.authenticate((org.springframework.security.core.Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        new ApiBadRequestException("An error occurred");
        new ApiBadRequestException("An error occurred");
        LoginRequest loginRequest = mock(LoginRequest.class);
        when(loginRequest.getPassword()).thenThrow(new BadCredentialsException("Msg"));
        when(loginRequest.getEmail()).thenReturn("jane.doe@example.org");
        assertThrows(ApiBadRequestException.class, () -> this.authServiceImpl.authenticateUser(loginRequest));
        verify(loginRequest).getEmail();
        verify(loginRequest).getPassword();
    }

    @Test
    void testAuthenticateUser7() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any()))
                .thenThrow(new ApiBadRequestException("An error occurred"));
        when(this.authenticationManager.authenticate((Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou")));
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
    }

    @Test
    void testAuthenticateUser8() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any())).thenReturn("ABC123");
        ArrayList<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
        when(this.authenticationManager.authenticate((Authentication) any())).thenReturn(new TestingAuthenticationToken(
                new UserDetailsImpl(123L, "jane.doe@example.org", "iloveyou", grantedAuthorityList), "Credentials"));
        JwtRes actualAuthenticateUserResult = this.authServiceImpl
                .authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou"));
        assertEquals("ABC123", actualAuthenticateUserResult.getAccessToken());
        assertEquals("Bearer", actualAuthenticateUserResult.getTokenType());
        assertEquals(grantedAuthorityList, actualAuthenticateUserResult.getRoles());
        assertEquals(123L, actualAuthenticateUserResult.getId().longValue());
        assertEquals("jane.doe@example.org", actualAuthenticateUserResult.getEmail());
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
    }

    @Test
    void testAuthenticateUser9() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any())).thenReturn("ABC123");
        UserDetailsImpl userDetailsImpl = mock(UserDetailsImpl.class);
        when(userDetailsImpl.getEmail()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(userDetailsImpl.getId()).thenReturn(123L);
        when(userDetailsImpl.getAuthorities()).thenReturn(new ArrayList<>());
        TestingAuthenticationToken testingAuthenticationToken = new TestingAuthenticationToken(userDetailsImpl,
                "Credentials");

        when(this.authenticationManager.authenticate((Authentication) any())).thenReturn(testingAuthenticationToken);
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou")));
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
        verify(userDetailsImpl).getAuthorities();
        verify(userDetailsImpl).getEmail();
        verify(userDetailsImpl).getId();
    }

    @Test
    void testAuthenticateUser10() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any())).thenReturn("ABC123");
        UserDetailsImpl userDetailsImpl = mock(UserDetailsImpl.class);
        when(userDetailsImpl.getId()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(userDetailsImpl.getAuthorities()).thenReturn(new ArrayList<>());
        TestingAuthenticationToken testingAuthenticationToken = new TestingAuthenticationToken(userDetailsImpl,
                "Credentials", new ArrayList<>());

        when(this.authenticationManager.authenticate((Authentication) any())).thenReturn(testingAuthenticationToken);
        new ApiBadRequestException("An error occurred");
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou")));
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
        verify(userDetailsImpl).getAuthorities();
        verify(userDetailsImpl).getId();
    }

    @Test
    void testAuthenticateUser11() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((org.springframework.security.core.Authentication) any())).thenReturn("ABC123");
        when(this.authenticationManager.authenticate((org.springframework.security.core.Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        new ApiBadRequestException("An error occurred");
        new ApiBadRequestException("An error occurred");
        LoginRequest loginRequest = mock(LoginRequest.class);
        when(loginRequest.getPassword()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(loginRequest.getEmail()).thenReturn("jane.doe@example.org");
        assertThrows(ApiBadRequestException.class, () -> this.authServiceImpl.authenticateUser(loginRequest));
        verify(loginRequest).getEmail();
        verify(loginRequest).getPassword();
    }

    @Test
    void testAuthenticateUser12() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((org.springframework.security.core.Authentication) any())).thenReturn("ABC123");
        when(this.authenticationManager.authenticate((org.springframework.security.core.Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        new ApiBadRequestException("An error occurred");
        new ApiBadRequestException("An error occurred");
        LoginRequest loginRequest = mock(LoginRequest.class);
        when(loginRequest.getPassword()).thenThrow(new BadCredentialsException("Msg"));
        when(loginRequest.getEmail()).thenReturn("jane.doe@example.org");
        assertThrows(ApiBadRequestException.class, () -> this.authServiceImpl.authenticateUser(loginRequest));
        verify(loginRequest).getEmail();
        verify(loginRequest).getPassword();
    }

    @Test
    void testAuthenticateUser13() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any()))
                .thenThrow(new ApiBadRequestException("An error occurred"));
        when(this.authenticationManager.authenticate((Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou")));
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
    }

    @Test
    void testAuthenticateUser14() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any())).thenReturn("ABC123");
        ArrayList<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
        when(this.authenticationManager.authenticate((Authentication) any())).thenReturn(new TestingAuthenticationToken(
                new UserDetailsImpl(123L, "jane.doe@example.org", "iloveyou", grantedAuthorityList), "Credentials"));
        JwtRes actualAuthenticateUserResult = this.authServiceImpl
                .authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou"));
        assertEquals("ABC123", actualAuthenticateUserResult.getAccessToken());
        assertEquals("Bearer", actualAuthenticateUserResult.getTokenType());
        assertEquals(grantedAuthorityList, actualAuthenticateUserResult.getRoles());
        assertEquals(123L, actualAuthenticateUserResult.getId().longValue());
        assertEquals("jane.doe@example.org", actualAuthenticateUserResult.getEmail());
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
    }

    @Test
    void testAuthenticateUser15() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any())).thenReturn("ABC123");
        UserDetailsImpl userDetailsImpl = mock(UserDetailsImpl.class);
        when(userDetailsImpl.getEmail()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(userDetailsImpl.getId()).thenReturn(123L);
        when(userDetailsImpl.getAuthorities()).thenReturn(new ArrayList<>());
        TestingAuthenticationToken testingAuthenticationToken = new TestingAuthenticationToken(userDetailsImpl,
                "Credentials");

        when(this.authenticationManager.authenticate((Authentication) any())).thenReturn(testingAuthenticationToken);
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou")));
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
        verify(userDetailsImpl).getAuthorities();
        verify(userDetailsImpl).getEmail();
        verify(userDetailsImpl).getId();
    }

    @Test
    void testAuthenticateUser16() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((Authentication) any())).thenReturn("ABC123");
        UserDetailsImpl userDetailsImpl = mock(UserDetailsImpl.class);
        when(userDetailsImpl.getId()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(userDetailsImpl.getAuthorities()).thenReturn(new ArrayList<>());
        TestingAuthenticationToken testingAuthenticationToken = new TestingAuthenticationToken(userDetailsImpl,
                "Credentials", new ArrayList<>());

        when(this.authenticationManager.authenticate((Authentication) any())).thenReturn(testingAuthenticationToken);
        new ApiBadRequestException("An error occurred");
        assertThrows(ApiBadRequestException.class,
                () -> this.authServiceImpl.authenticateUser(new LoginRequest("jane.doe@example.org", "iloveyou")));
        verify(this.jwtUtils).generateJwtToken((Authentication) any());
        verify(this.authenticationManager).authenticate((Authentication) any());
        verify(userDetailsImpl).getAuthorities();
        verify(userDetailsImpl).getId();
    }

    @Test
    void testAuthenticateUser17() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((org.springframework.security.core.Authentication) any())).thenReturn("ABC123");
        when(this.authenticationManager.authenticate((org.springframework.security.core.Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        new ApiBadRequestException("An error occurred");
        new ApiBadRequestException("An error occurred");
        LoginRequest loginRequest = mock(LoginRequest.class);
        when(loginRequest.getPassword()).thenThrow(new ApiBadRequestException("An error occurred"));
        when(loginRequest.getEmail()).thenReturn("jane.doe@example.org");
        assertThrows(ApiBadRequestException.class, () -> this.authServiceImpl.authenticateUser(loginRequest));
        verify(loginRequest).getEmail();
        verify(loginRequest).getPassword();
    }

    @Test
    void testAuthenticateUser18() throws AuthenticationException {
        when(this.jwtUtils.generateJwtToken((org.springframework.security.core.Authentication) any())).thenReturn("ABC123");
        when(this.authenticationManager.authenticate((org.springframework.security.core.Authentication) any()))
                .thenReturn(new TestingAuthenticationToken("Principal", "Credentials"));
        new ApiBadRequestException("An error occurred");
        new ApiBadRequestException("An error occurred");
        LoginRequest loginRequest = mock(LoginRequest.class);
        when(loginRequest.getPassword()).thenThrow(new BadCredentialsException("Msg"));
        when(loginRequest.getEmail()).thenReturn("jane.doe@example.org");
        assertThrows(ApiBadRequestException.class, () -> this.authServiceImpl.authenticateUser(loginRequest));
        verify(loginRequest).getEmail();
        verify(loginRequest).getPassword();
    }
}

