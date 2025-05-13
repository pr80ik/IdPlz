package com.example.idplz.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http
           .authorizeHttpRequests(authorizeRequests ->
               authorizeRequests
                   .requestMatchers("/saml/**", "/login", "/css/**", "/js/**", "/error").permitAll() // Allow access to SAML endpoints and login
                   .anyRequest().authenticated()
           )
           .formLogin(withDefaults()); // Simple form login for any other protected resources (not used for SAML)

       // For SAML IdP, CSRF might need to be disabled for the SAML SSO POST endpoint
       // if SPs are sending standard POST requests.
       // For a test server, this is often acceptable. For production, more care is needed.
       http.csrf(csrf -> csrf.ignoringRequestMatchers("/saml/sso"));

       return http.build();
   }
}