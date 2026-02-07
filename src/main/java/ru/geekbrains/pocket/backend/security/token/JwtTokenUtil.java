package ru.geekbrains.pocket.backend.security.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import ru.geekbrains.pocket.backend.domain.db.User;

import java.io.Serializable;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtTokenUtil implements Serializable {
    private static final long ACCESS_TOKEN_VALIDITY_MILLISECONDS = 30*24*60*60*1000L;//30 дней
    private static final String SIGNING_KEY = "pocket";

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(SIGNING_KEY)
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public String generateToken(User user) {
        return doGenerateToken(user);
    }

    private String doGenerateToken(User user) {

        Claims claims = Jwts.claims().setSubject(user.getEmail());
        //claims.put("scopes", user.getRoles()); // Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")));

        return Jwts.builder()
                .setClaims(claims)
                .setIssuer("http://geekbrains.ru")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY_MILLISECONDS))
                .signWith(SignatureAlgorithm.HS256, SIGNING_KEY)
                .compact();

    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (
              username.equals(userDetails.getUsername())
                    && !isTokenExpired(token));
    }

    public Boolean validateToken(String token, String userName) {
        final String username = getUsernameFromToken(token);
        return (
                username.equals(userName)
                        && !isTokenExpired(token));
    }

}
