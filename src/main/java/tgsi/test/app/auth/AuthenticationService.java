package tgsi.test.app.auth;

import tgsi.test.app.config.JwtService;
import tgsi.test.app.token.Token;
import tgsi.test.app.token.TokenMapper;
import tgsi.test.app.token.TokenType;
import tgsi.test.app.user.User;
import tgsi.test.app.user.UserMapper;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  // private final UserRepository repository;
  private final UserMapper userMapper;
  private final TokenMapper tokenMapper;
  // private final TokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public Boolean isAuthenticated(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
    Cookie[] cookies = httpServletRequest.getCookies();
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (cookie.getName().equals("accessToken")) {
          String accessToken = cookie.getValue();
          try {
            jwtService.extractUsername(accessToken);
          } catch (Exception e) {
            System.out.println("accessToken is invalid");
            return false;
          }
          String userEmail = jwtService.extractUsername(accessToken);
          if (userEmail != null) {
            User user = this.userMapper.findByEmail(userEmail);
            Boolean isAuth = jwtService.isTokenValid(accessToken, user);
            System.out.println("isAuthenticated: " + isAuth);
            // httpServletResponse.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " +
            // accessToken);

            // httpServletRequest.setAttribute(HttpHeaders.AUTHORIZATION, "Bearer " +
            // accessToken);
            return isAuth;
          }
        }
      }
    }
    return false; // refreshToken cookie not found
  }

  public HashMap<String, String> getAllCookies(HttpServletRequest httpServletRequest) {
    HashMap<String, String> cookies = new HashMap<>();
    Cookie[] cookieList = httpServletRequest.getCookies();
    if (cookieList != null) {
      for (Cookie cookie : cookieList) {
        cookies.put(cookie.getName(), cookie.getValue());
      }
    }
    return cookies;
  }

  public AuthenticationResponse register(RegisterRequest request) {
    System.out.println("AuthenticationService.register");

    var user = User.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(request.getRole())
        .build();
    // var savedUser = repository.save(user);
    try {
      userMapper.insertUser(user);
      System.out.println(">>>>BUILD<<<<");
      var jwtToken = jwtService.generateToken(user);
      var refreshToken = jwtService.generateRefreshToken(user);
      saveUserToken(user, jwtToken);
      return AuthenticationResponse.builder()
          .accessToken(jwtToken)
          .refreshToken(refreshToken)
          .build();
    } catch (Exception e) {
      System.out.println("AuthenticationService.register");
      System.out.println(e.getMessage());
      return null;

    }

  }

  public AuthenticationResponse authenticateUsingRefreshTokenCookie(
      HttpServletRequest request,
      HttpServletResponse response) throws IOException {
    System.out.println("AuthenticationService.authenticateusingrefreshtokencookie");
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    final String refreshToken;
    final String userEmail;
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return null;
    }
    refreshToken = authHeader.substring(7);
    userEmail = jwtService.extractUsername(refreshToken);
    if (userEmail != null) {
      User user = this.userMapper.findByEmail(userEmail);
      // .orElseThrow();
      if (jwtService.isTokenValid(refreshToken, user)) {
        var accessToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        var authResponse = AuthenticationResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .build();
        return authResponse;
      }
    }
    return null;
  }

  public AuthenticationResponse authenticate(AuthenticationRequest request, HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse) {

    System.out.println("AuthenticationService.authenticate");

    try {
      authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(
              request.getEmail(),
              request.getPassword()));
    } catch (AuthenticationException e) {
      System.out.println("AuthenticationService.authenticate");
      System.out.println(e.getMessage());
      // Handle authentication failure,

      // throw new Exception("Authentication failed", e);
      // email or password does not exist and will return null for validation
      return null;
    }
    System.out.println("findbyemail ");
    User user = userMapper.findByEmail(request.getEmail());
    // .orElseThrow();
    System.out.println(">>>>>>" + user.toString());
    var jwtToken = jwtService.generateToken(user);
    var refreshToken = jwtService.generateRefreshToken(user);
    revokeAllUserTokens(user);
    saveUserToken(user, jwtToken);

    Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
    refreshTokenCookie.setHttpOnly(true);
    refreshTokenCookie.setPath("/");
    refreshTokenCookie.setSecure(true); // only works on https
    refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
    httpServletResponse.addCookie(refreshTokenCookie);

    // httpServletResponse.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " +
    // jwtToken);

    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
        .refreshToken(refreshToken)
        .role(user.getRole())
        .email(user.getEmail())
        .build();

  }

  private void saveUserToken(User user, String jwtToken) {
    System.out.println("AuthenticationService.saveusertoken");
    var token = Token.builder()
        .user(user)
        .token(jwtToken)
        .token_type(TokenType.BEARER)
        .expired(false)
        .revoked(false)
        .user_id(user.getId())
        .build();
    tokenMapper.insertToken(token);
  }

  public void revokeAllUserTokens(User user) {
    System.out.println("AuthenticationService.revokeallusertoken");
    Integer userId = user.getId();
    List<Token> validUserTokens = tokenMapper.findAllValidTokenByUser(userId);

    if (!validUserTokens.isEmpty()) {
      // Update the tokens to set expired and revoked to true
      tokenMapper.updateTokens(validUserTokens);
    }
  }

  public void refreshToken(
      HttpServletRequest request,
      HttpServletResponse response) throws IOException {
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    final String refreshToken;
    final String userEmail;
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return;
    }
    refreshToken = authHeader.substring(7);
    userEmail = jwtService.extractUsername(refreshToken);
    if (userEmail != null) {
      User user = this.userMapper.findByEmail(userEmail);
      // .orElseThrow();
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
