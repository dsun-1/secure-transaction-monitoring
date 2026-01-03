package com.security.tests.api;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.testng.annotations.Test;

public class RateLimitingTest extends BaseTest {
    
    @Test(description = "Test rate limiting on API endpoints")
    public void testRateLimiting() {
        RestAssured.baseURI = baseUrl;
        
        // Test rate limiting by making rapid requests
        int requestCount = 100;
        int tooManyRequestsCount = 0;
        
        for (int i = 0; i < requestCount; i++) {
            Response response = RestAssured
                .given()
                .get("/products");
            
            if (response.statusCode() == 429) { // Too Many Requests
                tooManyRequestsCount++;
            }
        }
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "RATE_LIMITING_TEST",
            "test_user",
            "dos_protection_test",
            "Tested rate limiting: " + tooManyRequestsCount + " requests blocked out of " + requestCount
        );
        eventLogger.logSecurityEvent(event);
    }
}
