package com.prgrms.devcourse.config;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import static org.springframework.security.authorization.AuthenticatedAuthorizationManager.fullyAuthenticated;
import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;

@Slf4j
@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/me").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/admin").access(allOf(fullyAuthenticated(), hasRole("ADMIN")))
                        .anyRequest().permitAll()
                )
                .formLogin(form -> form
                        .defaultSuccessUrl("/")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                )
                .rememberMe(remember -> remember
                        .tokenValiditySeconds(300)
                )
                .requiresChannel(channel -> channel
                        .anyRequest().requiresSecure()
                )
                .sessionManagement(session -> session
                        .sessionFixation().changeSessionId() // default
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // default
                        .invalidSessionUrl("/")
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false) // default
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .accessDeniedHandler(accessDeniedHandler())
                );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user =
                User.withDefaultPasswordEncoder()
                        .username("user")
                        .password("user123")
                        .roles("USER")
                        .build();

        UserDetails admin =
                User.withDefaultPasswordEncoder()
                        .username("admin")
                        .password("admin123")
                        .roles("ADMIN")
                        .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return ((request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principle = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{}  is denied", principle, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        } );
    }
}
