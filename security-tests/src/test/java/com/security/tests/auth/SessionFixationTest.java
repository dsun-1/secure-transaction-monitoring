package com.security.tests.auth;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import org.openqa.selenium.Cookie;
import org.testng.Assert;
import org.testng.annotations.Test;

public class SessionFixationTest extends BaseTest {
    
    @Test(description = "Test session fixation protection")
    public void testSessionFixation() {
        navigateToUrl("/login");
        
        // Get session ID before login
        Cookie sessionBefore = driver.manage().getCookieNamed("JSESSIONID");
        String sessionIdBefore = sessionBefore != null ? sessionBefore.getValue() : null;
        
        // Login
        navigateToUrl("/login");
        
        // Get session ID after login
        Cookie sessionAfter = driver.manage().getCookieNamed("JSESSIONID");
        String sessionIdAfter = sessionAfter != null ? sessionAfter.getValue() : null;
        
        // Session ID should change after authentication
        Assert.assertNotEquals(sessionIdAfter, sessionIdBefore,
            "Session ID should change after login to prevent session fixation");
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "SESSION_FIXATION_TEST",
            "test_user",
            "session_management_test",
            "Tested session fixation protection"
        );
        eventLogger.logSecurityEvent(event);
    }
}
