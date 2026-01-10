package com.security.tests.auth;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import java.time.Duration;
import org.testng.Assert;
import org.testng.annotations.Test;

public class SessionFixationTest extends BaseTest {
    
    @Test(description = "Test session fixation protection")
    public void testSessionFixation() {
        navigateToUrl("/login");
        
        
        Cookie sessionBefore = driver.manage().getCookieNamed("JSESSIONID");
        String sessionIdBefore = sessionBefore != null ? sessionBefore.getValue() : null;
        
        
        navigateToUrl("/login"); 
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        
        new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(ExpectedConditions.or(
                ExpectedConditions.urlContains("/products"),
                ExpectedConditions.urlContains("/cart")
            ));


        
        Cookie sessionAfter = driver.manage().getCookieNamed("JSESSIONID");
        String sessionIdAfter = sessionAfter != null ? sessionAfter.getValue() : null;
        
        
        Assert.assertNotNull(sessionIdAfter, "Session ID should not be null after login");
        Assert.assertNotEquals(sessionIdAfter, sessionIdBefore,
            "Session ID should change after login to prevent session fixation");
        assertSecurityEventLogged("SESSION_FIXATION_ATTEMPT");

    }

}
