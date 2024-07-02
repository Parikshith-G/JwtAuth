package com.authentication_authorization.controller;

import com.authentication_authorization.config.JwtGenerationValidator;
import com.authentication_authorization.dto.UserDTO;
import com.authentication_authorization.entities.User;
import com.authentication_authorization.exceptions.AppException;
import com.authentication_authorization.repository.UserRepository;
import com.authentication_authorization.service.contract.IDefaultUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin
public class Endpoints {

    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    private final JwtGenerationValidator jwtGenerationValidator;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final IDefaultUserService userService;

    @Autowired
    public Endpoints(UserRepository userRepository, AuthenticationManager authenticationManager, JwtGenerationValidator jwtGenerationValidator, BCryptPasswordEncoder bCryptPasswordEncoder, IDefaultUserService userService) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtGenerationValidator = jwtGenerationValidator;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userService = userService;
    }

    @PostMapping("/registration")
    public ResponseEntity<Object> registerUser(@RequestBody UserDTO dto) {

        User user = userService.save(dto);
        System.err.print(user);
        if (user == null) {
            return generateResponse("Not able to save user", HttpStatus.BAD_REQUEST, dto, "");
        } else {
//            UsernamePasswordAuthenticationToken token=new UsernamePasswordAuthenticationToken(dto.email(),
//                    dto.password());
//            String jwtToken = jwtGenerationValidator.generateToken(token);
            return generateResponse("User saved with id " + user.getId(), HttpStatus.CREATED, user, "");
        }
    }



    @PostMapping("/login")
    public ResponseEntity<Object> generateJwtToken(@RequestBody UserDTO dto) {
        System.err.println("here 1");
        UsernamePasswordAuthenticationToken token=new UsernamePasswordAuthenticationToken(dto.email(),
                dto.password());
        try {
            Authentication authentication = authenticationManager.authenticate(token);
            System.err.println("here 2");

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String _token= jwtGenerationValidator.generateToken(authentication);
            return generateResponse("Login successful",HttpStatus.OK,null,_token);
        }
        catch (AppException e){
            return generateResponse("Login failure",HttpStatus.UNAUTHORIZED,null,null);
        }
    }

    @GetMapping("/welcomeAdmin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String welcome() {
        return "WelcomeAdmin";
    }

    @GetMapping("/welcomeUser")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String welcomeUser() {
        return "WelcomeUSER";
    }

    private ResponseEntity<Object> generateResponse(String message, HttpStatus httpStatus, Object responseObj, String token) {
        Map<String, Object> map = new HashMap<>();
        map.put("Message", message);
        map.put("Status", httpStatus.value());
        map.put("Data", responseObj);
        map.put("Token", token);

        return new ResponseEntity<>(map, httpStatus);
    }
}