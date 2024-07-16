package app.authserver.jwt;

import app.authserver.security.CustomUserDetails;
import app.authserver.security.CustomUserDetailsService;
import app.authserver.config.RedisConfig;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.data.redis.core.RedisTemplate;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.concurrent.TimeUnit;
import java.util.UUID;

@Component
public class JwtUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expireMs}")
    private int jwtExpirationMs;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    private final RedisTemplate<String, Object> redisTemplate;

    @Autowired
    public JwtUtils(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
    public String generateJwtToken(UUID userId) { return generateTokenFromUserId(userId);}

    public String generateTokenFromUserId(UUID userId) {
        UserDetails userDetails = customUserDetailsService.loadUserById(userId);
        StringBuilder roles = new StringBuilder();
        userDetails.getAuthorities().forEach(role -> roles.append(role.getAuthority()).append(" "));

        return Jwts.builder()
                .setSubject(userId.toString())
                .setIssuer(roles.toString())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public UUID getUserIdFromJwtToken(String token) {
        String userIdString = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
        return UUID.fromString(userIdString);
    }

    public boolean validateJwtToken(String authToken) {
        try {
            UUID userId = getUserIdFromJwtToken(authToken);
            String storedToken = getToken(userId.toString());
            System.out.println("Stored token for userId " + userId + ": " + storedToken);
            if (storedToken == null || !storedToken.equals(authToken)) {
                LOGGER.error("JwtUtils | validateJwtToken | Token not found in Redis or does not match");
                return false;
            }
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            LOGGER.error("JwtUtils | validateJwtToken | Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            LOGGER.error("JwtUtils | validateJwtToken | Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            LOGGER.error("JwtUtils | validateJwtToken | JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            LOGGER.error("JwtUtils | validateJwtToken | JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            LOGGER.error("JwtUtils | validateJwtToken | JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    public void saveToken(UUID userId, String token) {
        redisTemplate.opsForValue().set(userId.toString(), token, jwtExpirationMs, TimeUnit.MILLISECONDS);
    }

    public String getToken(String userId) {
        Object token = redisTemplate.opsForValue().get(userId);
        return token != null ? token.toString() : null;
    }

    public void deleteToken(UUID userId) {
        redisTemplate.delete(userId.toString());
    }
}
