package ru.geekbrains.pocket.backend.security;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

//https://www.baeldung.com/spring-security-block-brute-force-authentication-attempts
//неудачная попытка аутентификации увеличивает количество попыток для этого IP-адреса,
// и успешная аутентификация сбрасывает этот счетчик.

@Service
public class LoginAttemptService {

    private final int MAX_ATTEMPT = 10;
    private final LoadingCache<String, Integer> attemptsCache;

    public LoginAttemptService() {
        attemptsCache = Caffeine.newBuilder()
                .expireAfterWrite(1, TimeUnit.DAYS)
                .build(key -> 0); // Дефолтное значение
    }

    public void loginSucceeded(final String key) {
        attemptsCache.invalidate(key);
    }

    private int getAttempts(String key) {
        return Optional.ofNullable(attemptsCache.get(key)).orElse(0);
    }

    public void loginFailed(final String key) {
        int attempts = getAttempts(key);
        attempts++;
        attemptsCache.put(key, attempts);
    }

    public boolean isBlocked(final String key) {
        return getAttempts(key) >= MAX_ATTEMPT;
    }
}
