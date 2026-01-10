package com.security.tests.injection;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.time.Duration;

public class SQLInjectionTest extends BaseTest {
    
    @Test(description = "Test SQL injection in login form")
    public void testSQLInjectionLogin() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        String[] sqlPayloads = {
            "' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "' UNION SELECT NULL--"
        };
        
        for (String payload : sqlPayloads) {
            navigateToUrl("/login");
            WebElement username = wait.until(ExpectedConditions.elementToBeClickable(By.id("username")));
            WebElement password = driver.findElement(By.id("password"));
            WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
            
            username.clear();
            username.sendKeys(payload);
            password.clear();
            password.sendKeys("password");
            loginButton.click();
            
            wait.until(ExpectedConditions.urlContains("/login"));
            String currentUrl = driver.getCurrentUrl();
            Assert.assertTrue(currentUrl.contains("/login"), 
                "SQL injection should not bypass authentication");
        }
        
        assertSecurityEventLogged("SQL_INJECTION_ATTEMPT");
    }
    
    @Test(description = "Test SQL injection in search parameters")
    public void testSQLInjectionSearch() {
        String payload = "' OR '1'='1";
        navigateToUrl("/products?search=" + payload);

        String pageSource = driver.getPageSource();
        Assert.assertFalse(pageSource.contains(payload), 
            "Search payload should not be reflected in page output");
        Assert.assertFalse(pageSource.toLowerCase().contains("sql"),
            "SQL errors should not be exposed in responses");

        assertSecurityEventLogged("SQL_INJECTION_ATTEMPT");
    }

}
