package com.security.ecommerce;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Simple test to verify the application context loads successfully.
 * If this test passes, it means the Spring Boot application can start without errors.
 */
@SpringBootTest
class ApplicationStartupTest {

    @Test
    void contextLoads() {
        // If this test passes, the Spring application context loaded successfully
        // This verifies:
        // - All beans are properly configured
        // - Dependencies are correctly wired
        // - No configuration errors exist
    }
    
    @Test
    void applicationStarts() {
        // Another basic test to ensure the application can initialize
        // This is useful for CI/CD pipelines to verify deployment readiness
    }
}
