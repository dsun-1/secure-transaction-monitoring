package com.security.tests.listeners;

import org.testng.ITestContext;
import org.testng.ITestListener;
import org.testng.ITestResult;

/**
 * Listener to capture security events during test execution
 */
public class SecurityEventListener implements ITestListener {
    
    @Override
    public void onTestFailure(ITestResult result) {
        // Log security vulnerability when test fails
        System.out.println("Security test failed: " + result.getName());
    }
}
