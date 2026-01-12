package com.jesussb.jwt_security_demo.common.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class JwtStore {

    private final StringRedisTemplate template;

    public void revoke(String jti, Duration ttl){
        template.opsForValue().set("revoked:jti:"+jti, "1", ttl);
    }

    public boolean isRevoked(String jti) {
        return Boolean.TRUE.equals(template.hasKey("revoked:jti:" + jti));
    }

}
