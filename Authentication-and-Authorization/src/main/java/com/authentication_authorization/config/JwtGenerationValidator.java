package com.authentication_authorization.config;

import com.authentication_authorization.service.contract.IDefaultUserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtGenerationValidator {

    private final IDefaultUserService userService;
    private final String SECRET = "eiffcicefhccfhifiwpzwmfm843y47398t598785cm548x4x3xtxtm8xtmxrqmyw8241m";

    @Autowired
    public JwtGenerationValidator(IDefaultUserService userService) {
        this.userService = userService;
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Claims extractUserRole(String token) {
        return extractAlLClaims(token);
    }

    public Date extractExpirationDate(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAlLClaims(token);
        return claimResolver.apply(claims);
    }

    public Claims extractAlLClaims(String token) {
        SecretKey secretKey = generateSecretKey();
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
    }

    public Boolean isTokenExpired(String token) {
        return extractExpirationDate(token).before(new Date());
    }

    public String generateToken(Authentication authentication) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, authentication);
    }

    public String createToken(Map<String, Object> claims, Authentication authentication) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + 3_600_000);
        String role = authentication
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet())
                .iterator().next();
        return Jwts.builder()
                .claim("role", role)
                .setSubject(authentication.getName())
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(generateSecretKey())
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);

        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public SecretKey generateSecretKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET));
    }

    public UsernamePasswordAuthenticationToken getAuthenticationToken(String token, Authentication existingAuth, UserDetails userDetails) {
        Claims claims = extractAlLClaims(token);
        final Collection<? extends GrantedAuthority> authorities = Arrays.stream(
                claims.get("role")
                        .toString()
                        .split(",")
        ).map(SimpleGrantedAuthority::new).toList();
        return new UsernamePasswordAuthenticationToken(userDetails, existingAuth, authorities);

    }


}