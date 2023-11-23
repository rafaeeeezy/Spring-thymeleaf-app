package tgsi.test.app.config;

import tgsi.test.app.user.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

  private final UserMapper mapper;

  @Bean
  public UserDetailsService userDetailsService() {
    System.out.println("ApplicationConfig.userdetailservice");
    return username -> mapper.findByEmail(username);
    // .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }

  @Bean
  public AuthenticationProvider authenticationProvider() {
    System.out.println("ApplicationConfig.authenticationprovider");
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService());
    authProvider.setPasswordEncoder(passwordEncoder());
    return authProvider;
  }

  // @Bean
  // public AuditorAware<Integer> auditorAware() {
  // return new ApplicationAuditAware();
  // }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    System.out.println("ApplicationConfig.authenticationmanager");
    return config.getAuthenticationManager();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    System.out.println("ApplicationConfig.passwordencoder");
    return new BCryptPasswordEncoder();
  }

}
