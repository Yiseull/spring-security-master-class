package com.prgrms.devcourse.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.Callable;

@Slf4j
@RestController
public class SimpleController {

    @GetMapping("/asyncHello")
    public Callable<String> asyncHello() {
        log.info("[Before callable] asyncHello started.");
        Callable<String> callable = () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            User principal = authentication != null ? (User) authentication.getPrincipal() : null;
            String name = principal != null ? principal.getUsername() : null;
            log.info("[Inside callable] Hello {}", name);
            return "Hello " + name;
        };
        log.info("[After callable] asyncHello completed.");
        return callable;
    }
}
