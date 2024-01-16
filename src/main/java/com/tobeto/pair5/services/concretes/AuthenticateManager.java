package com.tobeto.pair5.services.concretes;

import com.tobeto.pair5.config.JwtService;
import com.tobeto.pair5.core.utilities.mappers.ModelMapperService;
import com.tobeto.pair5.entities.concretes.User;
import com.tobeto.pair5.enums.Role;
import com.tobeto.pair5.services.abstracts.AuthenticationService;
import com.tobeto.pair5.services.abstracts.UserService;
import com.tobeto.pair5.services.dtos.auth.requests.AuthenticationRequest;
import com.tobeto.pair5.services.dtos.auth.requests.RegisterRequest;
import com.tobeto.pair5.services.dtos.auth.responses.AuthenticationResponse;
import com.tobeto.pair5.services.dtos.user.requests.AddUserRequest;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthenticateManager implements AuthenticationService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapperService modelMapperService;
    private final JwtService jwtService;
    private final AuthenticationManager manager;
    @Override
    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userService.add(this.modelMapperService.forRequest().map(user, AddUserRequest.class));
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        manager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userService.getByEmail(request.getEmail());
        var jwtToken = jwtService.generateToken(modelMapperService.forResponse().map(user, User.class));
        return AuthenticationResponse.builder()
                .token(jwtToken )
                .build();
    }
}
