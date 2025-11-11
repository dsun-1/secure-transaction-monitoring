package com.security.tests.injection;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import org.testng.Assert;
import org.testng.annotations.Test;

public class CSRFTest extends BaseTest {
    
    @Test(description = "Test CSRF token presence")
    public void testCSRFTokenPresent() {
        navigateToUrl("/login");
        
        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("_csrf") || pageSource.contains("csrf"),
            "CSRF token should be present in forms");
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "CSRF_TEST",
            "test_user",
            "security_test",
            "Tested CSRF token presence"
        );
        eventLogger.logSecurityEvent(event);
    }
}
