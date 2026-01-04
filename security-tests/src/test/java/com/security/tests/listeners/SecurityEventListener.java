package com.security.tests.listeners;

import org.testng.ITestContext;
import org.testng.ITestListener;
import org.testng.ITestResult;


public class SecurityEventListener implements ITestListener {
    
    @Override
    public void onTestFailure(ITestResult result) {
        
        System.out.println("Security test failed: " + result.getName());
    }
}
