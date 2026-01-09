package com.jesussb.jwt_security_demo.user;

import com.jesussb.jwt_security_demo.user.dto.LoginRequest;
import com.jesussb.jwt_security_demo.user.dto.LoginResponse;

public interface UserService {
    LoginResponse login(LoginRequest request);
}
