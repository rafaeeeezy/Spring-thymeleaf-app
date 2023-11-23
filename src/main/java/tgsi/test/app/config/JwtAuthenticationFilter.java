package tgsi.test.app.config;

import tgsi.test.app.token.TokenMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtService jwtService;
  private final UserDetailsService userDetailsService;
  // private final TokenRepository tokenRepository;
  private final TokenMapper tokenMapper;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    System.out.println("JwtAuthenticationFilter.dofilterinternal");
    if (request.getServletPath().contains("/auth/**") || request.getServletPath().contains("/logout")) {
      filterChain.doFilter(request, response);
      System.out.println("FILTER CHAIN");
      return;
    }
    final String authHeader = request.getHeader("Authorization");
    System.out.println("AUTH HEADER>>>>>>>>" + authHeader);
    final String jwt;
    final String userEmail;
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }
    jwt = authHeader.substring(7);
    userEmail = jwtService.extractUsername(jwt);
    System.out.println("EMAIL>>>>>>>>" + userEmail);
    if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
      var isTokenValid = !tokenMapper.findByToken(jwt).isExpired() && !tokenMapper.findByToken(jwt).isRevoked();
      // .map(t -> !t.isExpired() && !t.isRevoked());
      // .orElse(false);
      System.out.println("CHECK TOKEN VALID");
      if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
        System.out.println("TOKEN VALID");
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities());
        authToken.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
      }
    }
    filterChain.doFilter(request, response);
  }
}
