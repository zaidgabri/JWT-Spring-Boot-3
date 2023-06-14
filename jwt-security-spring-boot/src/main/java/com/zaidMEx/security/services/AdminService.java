package com.zaidMEx.security.services;

import com.zaidMEx.security.auth.RegisterRequest;
import com.zaidMEx.security.config.JwtService;

import com.zaidMEx.security.models.AgentResponse;
import com.zaidMEx.security.models.AgentRquest;
import com.zaidMEx.security.token.Token;
import com.zaidMEx.security.token.TokenRepository;
import com.zaidMEx.security.token.TokenType;
import com.zaidMEx.security.user.Role;
import com.zaidMEx.security.user.User;
import com.zaidMEx.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AdminService {
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;






    public String registerAgent(AgentRquest request) {
        if (!request.getEmail().equals(request.getConfirm_email())) {
            throw new IllegalArgumentException("Email and confirm email must match.");
        }

        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .confirm_email(request.getConfirm_email())
                .IdentityType(request.getIdentityType())
                .Num_Identity(request.getNum_Identity())
                .Birthday(request.getBirthday())
                .Address(request.getAddress())
                .RCS(request.getRCS())
                .Num_de_patente(request.getNum_de_patente())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.setRole(Role.valueOf(("AGENT"))))
                .tele(request.getTele())
                .build();

        var savedUser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        //  Role role = repository.getRoleByEmail(request.getEmail());
        saveAgentToken(savedUser, jwtToken);

        return "Agent Created Seccussufully";
    }
    private void saveAgentToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    public AgentResponse getAgentById(Integer id) {
        User agent=
                repository.findById(id)
                        .orElseThrow();

        AgentResponse agentResponse= AgentResponse.builder()
                .id(agent.getId())
                .firstname(agent.getFirstname())
                .lastname(agent.getLastname())
                .Num_de_patente(agent.getNum_de_patente())
                .tele(agent.getTele())
                .RCS(agent.getRCS())
                .Num_Identity(agent.getNum_Identity())
                .IdentityType(agent.getIdentityType())
                .Address(agent.getAddress())
                .Birthday(agent.getBirthday())
                .confirm_email(agent.getConfirm_email())
                .build();
        return  agentResponse;
    }

//    public ResponseEntity<String> updateAgent( AgentRquest userUpdateRequest) {
//        User agent=
//                repository.findById(userUpdateRequest.getId())
//                        .orElseThrow();
//        User updatedUser = User.builder()
//                .firstname(userUpdateRequest.getFirstname())
//                .lastname(userUpdateRequest.getLastname())
//                .email(userUpdateRequest.getEmail())
//                .confirm_email(userUpdateRequest.getConfirm_email())
//                .RCS(userUpdateRequest.getRCS())
//                .Address(userUpdateRequest.getAddress())
//                .Num_de_patente(userUpdateRequest.getNum_de_patente())
//                .Num_Identity(userUpdateRequest.getNum_Identity())
//                .IdentityType(userUpdateRequest.getIdentityType())
//                .Birthday(userUpdateRequest.getBirthday())
//                .password(userUpdateRequest.getPassword())
//                .tele(userUpdateRequest.getTele())
//                .build();
//
//        repository.save(updatedUser);
//
//            return ResponseEntity.ok("User updated successfully");
//        }
    }

