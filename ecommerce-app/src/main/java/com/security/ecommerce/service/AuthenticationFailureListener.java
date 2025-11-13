import com.security.ecommerce.model.User;
import org.springframework.lang.NonNull;
package com.security.ecommerce.service;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFailureListener implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {
    private final UserService userService;

    public AuthenticationFailureListener(UserService userService) {
        this.userService = userService;
    }

    @Override
    public void onApplicationEvent(@NonNull AuthenticationFailureBadCredentialsEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        if (principal instanceof String username) {
            User user = userService.findByUsername(username);
            if (user != null && !user.isAccountLocked()) {
                user.incrementFailedAttempts();
                userService.save(user);
            }
        }
    }
}
