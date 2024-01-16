package com.tobeto.pair5.services.abstracts;

import com.tobeto.pair5.services.dtos.auth.requests.AuthenticationRequest;
import com.tobeto.pair5.services.dtos.auth.requests.RegisterRequest;
import com.tobeto.pair5.services.dtos.auth.responses.AuthenticationResponse;

public interface AuthenticationService {

    AuthenticationResponse register(RegisterRequest request);
    AuthenticationResponse authenticate(AuthenticationRequest request);
}
