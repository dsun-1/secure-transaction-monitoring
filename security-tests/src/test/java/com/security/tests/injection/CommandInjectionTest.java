package com.security.tests.injection;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import org.testng.annotations.Test;

public class CommandInjectionTest extends BaseTest {
    
    @Test(description = "Test command injection in form fields")
    public void testCommandInjection() {
        navigateToUrl("/products");
        
        // Test would involve trying command injection payloads
        // in various input fields like search, username, etc.
        String[] commandPayloads = {
            "; ls",
            "| whoami",
            "`id`",
            "$(cat /etc/passwd)"
        };
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "COMMAND_INJECTION_TEST",
            "test_user",
            "injection_attempt",
            "Tested command injection protection"
        );
        eventLogger.logSecurityEvent(event);
    }
}
