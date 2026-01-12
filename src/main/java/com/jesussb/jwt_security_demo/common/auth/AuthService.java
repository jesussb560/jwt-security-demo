package com.jesussb.jwt_security_demo.common.auth;

import com.jesussb.jwt_security_demo.common.auth.dto.LoginRequest;
import com.jesussb.jwt_security_demo.common.auth.dto.LoginResponse;
import com.jesussb.jwt_security_demo.common.auth.dto.RevokeRequest;

public interface AuthService {
    LoginResponse login(LoginRequest request);
    RevokeResponse revoke(RevokeRequest request);
}
