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
        
        
        int requestCount = 100;
        int tooManyRequestsCount = 0;
        int successCount = 0;
        
        for (int i = 0; i < requestCount; i++) {
            Response response = RestAssured
                .given()
                .get("/products");
            
            if (response.statusCode() == 429) { 
                tooManyRequestsCount++;
            } else if (response.statusCode() == 200) {
                successCount++;
            } else {
                throw new AssertionError("Unexpected status code: " + response.statusCode());
            }
        }
        
        org.testng.Assert.assertTrue(tooManyRequestsCount > 0,
            "Rate limiting should trigger under burst traffic");
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "RATE_LIMITING_TEST",
            "test_user",
            "dos_protection_test",
            "Tested rate limiting: " + tooManyRequestsCount + " blocked, " + successCount + " allowed out of " + requestCount
        );
        eventLogger.logSecurityEvent(event);
    }
}
