package app.authserver.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${jwt.refrEshexpireMs}")
    private Long refreshTokenDurationMs;
    private final UserService userService;
    private final RedisTemplate<String, Object> redisTemplate;

    public String createRefreshToken(UUID userId) {
        String token = UUID.randomUUID().toString();
        long expiration = Instant.now().plusMillis(refreshTokenDurationMs).toEpochMilli();

        RefreshTokenData refreshTokenData = new RefreshTokenData(userId, expiration);

        redisTemplate.opsForValue().set("refreshToken:" + token, refreshTokenData, refreshTokenDurationMs, TimeUnit.MILLISECONDS);
        return token;
    }

    public boolean verifyExpiration(String token) {
        RefreshTokenData refreshTokenData = (RefreshTokenData) redisTemplate.opsForValue().get("refreshToken:" + token);
        if (refreshTokenData == null || refreshTokenData.getExpiryDate() < Instant.now().toEpochMilli()) {
            redisTemplate.delete("refreshToken:" + token);
            return false;
        }
        return true;
    }

    public RefreshTokenData getUserIdFromToken(String token) {
        RefreshTokenData refreshTokenData = (RefreshTokenData) redisTemplate.opsForValue().get("refreshToken:" + token);
        return refreshTokenData;
    }

    private static class RefreshTokenData {
        private UUID userId;
        private long expiryDate;

        public RefreshTokenData(UUID userId, long expiryDate) {
            this.userId = userId;
            this.expiryDate = expiryDate;
        }

        public UUID getUserId() {
            return userId;
        }

        public long getExpiryDate() {
            return expiryDate;
        }
    }
}
