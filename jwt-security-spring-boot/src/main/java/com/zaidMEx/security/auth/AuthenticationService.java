package com.zaidMEx.security.auth;

import com.zaidMEx.security.config.JwtService;
import com.zaidMEx.security.token.Token;
import com.zaidMEx.security.token.TokenRepository;
import com.zaidMEx.security.token.TokenType;
import com.zaidMEx.security.user.Role;
import com.zaidMEx.security.user.User;
import com.zaidMEx.security.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;


import java.io.IOException;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository repository;
  private final TokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public String registerADMIN(RegisterRequest request) {
    // Check if the email already exists in the repository
    if (repository.existsByEmail(request.getEmail())) {
      return "Email already exists.";
    }

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
            .role(Role.ADMIN)
            .tele(request.getTele())
            .build();

    var savedUser = repository.save(user);
    var jwtToken = jwtService.generateToken(user);
    var refreshToken = jwtService.generateRefreshToken(user);
    saveUserToken(savedUser, jwtToken);

    return "Registered successfully";
  }



  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    System.out.println("Test2");

    BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    String plaintextPassword = request.getPassword();
    String encodedPassword = passwordEncoder.encode(plaintextPassword);

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            encodedPassword
        )
    );
    System.out.println("Test3");
    var user = repository.findByEmail(request.getEmail())
        .orElseThrow(()->new RuntimeException("NOTHING"));
    System.out.println("Test4");
    var jwtToken = jwtService.generateToken(user);
    System.out.println("Test5");
    var refreshToken = jwtService.generateRefreshToken(user);
    System.out.println("Test6");
    revokeAllUserTokens(user);
    saveUserToken(user, jwtToken);
    System.out.println(AuthenticationResponse.builder()
            .accessToken(jwtToken)
            .refreshToken(refreshToken)
            .build());
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
            .refreshToken(refreshToken)
        .build();
  }

  private void saveUserToken(User user, String jwtToken) {
    var token = Token.builder()
        .user(user)
        .token(jwtToken)
        .tokenType(TokenType.BEARER)
        .expired(false)
        .revoked(false)
        .build();
    tokenRepository.save(token);
  }

  private void revokeAllUserTokens(User user) {
    var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
    if (validUserTokens.isEmpty())
      return;
    validUserTokens.forEach(token -> {
      token.setExpired(true);
      token.setRevoked(true);
    });
    tokenRepository.saveAll(validUserTokens);
  }

  public void refreshToken(
          HttpServletRequest request,
          HttpServletResponse response
  ) throws IOException {
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    final String refreshToken;
    final String userEmail;
    if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
      return;
    }
    refreshToken = authHeader.substring(7);
    userEmail = jwtService.extractUsername(refreshToken);
    if (userEmail != null) {
      var user = this.repository.findByEmail(userEmail)
              .orElseThrow();
      if (jwtService.isTokenValid(refreshToken, user)) {
        var accessToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        var authResponse = AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
      }
    }
  }
}
