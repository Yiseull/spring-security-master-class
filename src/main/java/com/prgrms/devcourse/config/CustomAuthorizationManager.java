package com.prgrms.devcourse.config;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public final class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private static final Pattern PATTERN = Pattern.compile("[0-9]+$");

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        boolean decision = isOddAdmin(authentication.get());
        if (decision) {
            return new AuthorizationDecision(true);
        }
       return new AuthorizationDecision(false);
    }

    private boolean isOddAdmin(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String username = userDetails.getUsername();
        Matcher matcher = PATTERN.matcher(username);
        if (matcher.find()) {
            int number = Integer.parseInt(matcher.group());
            return number % 2 == 1;
        }
        return false;
    }
}
