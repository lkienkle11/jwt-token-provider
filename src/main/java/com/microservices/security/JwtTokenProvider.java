package com.microservices.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class JwtTokenProvider {
    private static Logger log;

    private final Key key;

    public JwtTokenProvider(String secret) {
        this(secret, false);
    }

    public JwtTokenProvider(String secret, boolean writeLog) {
        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("JWT secret cannot be null or empty");
        }
        // HMAC-SHA key
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        log = writeLog ? LoggerFactory.getLogger(JwtTokenProvider.class) : null;
    }

    public String generateToken(String subject, Map<String, Object> extraClaims, long expirationMillis) {
        long now = System.currentTimeMillis();
        JwtBuilder builder = Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(subject)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + expirationMillis))
                .signWith(key, SignatureAlgorithm.HS256);

        if (extraClaims != null) {
            builder.addClaims(extraClaims);
        }

        return builder.compact();
    }


    public String getUsernameFromJWT(String token) {
        return parseClaims(token).getSubject();
    }

    public Map<String, Object> getPropertiesFromClaims(String token) {
        Claims claims = parseClaims(token);
        Map<String, Object> props = new HashMap<>();
        props.put("uid",       claims.get("uid"));
        props.put("type",      claims.get("type"));
        props.put("jti",       claims.getId());
        props.put("createdAt", Instant.now().toEpochMilli());
        props.put("created_at", Instant.now().toEpochMilli());
        return props;
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (SignatureException ex) {
            if (log != null) {
                log.error("Invalid JWT signature: {}", ex.getMessage());
            }
        } catch (MalformedJwtException ex) {
            if (log != null) {
                log.error("Invalid JWT token: {}", ex.getMessage());
            }
        } catch (ExpiredJwtException ex) {
            if (log != null) {
                log.error("Expired JWT token: {}", ex.getMessage());
            }
            throw ex;  // cho phép ứng dụng xử lý riêng khi hết hạn
        } catch (UnsupportedJwtException ex) {
            if (log != null) {
                log.error("Unsupported JWT token: {}", ex.getMessage());
            }
        } catch (IllegalArgumentException ex) {
            if (log != null) {
                log.error("JWT claims string is empty: {}", ex.getMessage());
            }
        } catch (Exception ex) {
            if (log != null) {
                log.error("JWT token validation error: {}", ex.getMessage());
            }
        }
        return false;
    }


    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Claims parseClaimsAllowExpired(String token) {
        try {
            return parseClaims(token);
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}
