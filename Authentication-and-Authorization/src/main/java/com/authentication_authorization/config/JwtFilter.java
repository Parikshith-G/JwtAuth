package com.authentication_authorization.config;

import com.authentication_authorization.service.contract.IDefaultUserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final IDefaultUserService service;

    private final JwtGenerationValidator jwtGenerationValidator;


    @Autowired
    public JwtFilter(IDefaultUserService service, JwtGenerationValidator jwtGenerationValidator) {
        this.service = service;
        this.jwtGenerationValidator = jwtGenerationValidator;
    }


    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws
            ServletException,
            IOException {

        String header = request.getHeader("Authorization");
        String token = null;
        String userName = null;
//        Authentication authentication=SecurityContextHolder.getContext().getAuthentication();

        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
            userName = jwtGenerationValidator.extractUsername(token);
        }
        if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = service.loadUserByUsername(userName);
            if (jwtGenerationValidator.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = jwtGenerationValidator
                        .getAuthenticationToken(
                                token,
                                SecurityContextHolder
                                        .getContext()
                                        .getAuthentication(),
                                userDetails);
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }

        filterChain.doFilter(request, response);


    }
}
