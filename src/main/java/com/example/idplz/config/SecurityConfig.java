package com.example.idplz.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.actuate.metrics.MetricsEndpoint;
import org.springframework.boot.actuate.metrics.export.prometheus.PrometheusScrapeEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http
           .authorizeHttpRequests(authorizeRequests ->
               authorizeRequests
                   .requestMatchers("/saml/**", "/login", "/css/**", "/js/**", "/error").permitAll() // Allow access to SAML endpoints and login
                   .requestMatchers(EndpointRequest.to(HealthEndpoint.class)).permitAll()
                   .requestMatchers(EndpointRequest.to(InfoEndpoint.class)).permitAll()
                   .requestMatchers(EndpointRequest.to(PrometheusScrapeEndpoint.class)).permitAll()
                   .requestMatchers(EndpointRequest.to(MetricsEndpoint.class)).permitAll()
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