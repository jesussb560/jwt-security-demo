package com.jesussb.jwt_security_demo.common.auth;

import com.jesussb.jwt_security_demo.common.auth.dto.*;
import com.jesussb.jwt_security_demo.refreshtoken.RefreshToken;

public interface AuthService {
    LoginResponse login(LoginRequest request);
    RevokeResponse revoke(RevokeRequest request);
    RefreshResponse refresh(RefreshRequest request);
}
