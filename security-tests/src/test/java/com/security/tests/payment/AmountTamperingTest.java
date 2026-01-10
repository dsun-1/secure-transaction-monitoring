package com.security.tests.payment;

import com.security.tests.base.BaseTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.time.Duration;



public class AmountTamperingTest extends BaseTest {
    
    @Test(priority = 1, description = "Test client-side price modification via DOM manipulation")
    public void testClientSidePriceModification() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("paymentuser");
        driver.findElement(By.id("password")).sendKeys("Paym3nt@123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));
        


        
        navigateToUrl("/products");
        
        
        WebElement laptopRow = wait.until(
            ExpectedConditions.presenceOfElementLocated(By.xpath("//tr[contains(., 'Premium Laptop')]")
        ));
        WebElement addToCartForm = laptopRow.findElement(By.tagName("form"));
        
        
        WebElement addButton = addToCartForm.findElement(By.tagName("button"));
        addButton.click();

        wait.until(ExpectedConditions.urlContains("/products"));


        
        navigateToUrl("/cart");
        if (driver.getPageSource().contains("Your cart is empty")) {
            
            navigateToUrl("/products");
            laptopRow = wait.until(
                ExpectedConditions.presenceOfElementLocated(By.xpath("//tr[contains(., 'Premium Laptop')]")
            ));
            addToCartForm = laptopRow.findElement(By.tagName("form"));
            addButton = addToCartForm.findElement(By.tagName("button"));
            addButton.click();
            wait.until(ExpectedConditions.urlContains("/products"));

            navigateToUrl("/cart");
            Assert.assertFalse(driver.getPageSource().contains("Your cart is empty"),
                "Cart is still empty after retry; add-to-cart did not persist.");
        }
        

        
        navigateToUrl("/checkout");

        if (driver.getCurrentUrl().contains("/login")) {
            driver.findElement(By.id("username")).sendKeys("paymentuser");
            driver.findElement(By.id("password")).sendKeys("Paym3nt@123");
            driver.findElement(By.xpath("//button[@type='submit']")).click();
            wait.until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));

            
            navigateToUrl("/products");
            WebElement loginRetryRow = wait.until(
                ExpectedConditions.presenceOfElementLocated(By.xpath("//tr[contains(., 'Premium Laptop')]")
            ));
            WebElement retryForm = loginRetryRow.findElement(By.tagName("form"));
            retryForm.findElement(By.tagName("button")).click();
            wait.until(ExpectedConditions.urlContains("/products"));

            navigateToUrl("/checkout");
        }
        

        
        if (driver.getCurrentUrl().contains("/cart")) {
            Assert.fail("Test failed: Redirected to /cart. The item was not added successfully.");
        }
        

        
        WebElement totalElement = wait.until(
            ExpectedConditions.presenceOfElementLocated(By.xpath("//div[@class='total']/span")
        ));
        String originalTotal = totalElement.getText();
        Assert.assertEquals(originalTotal, "999.99", "Original price should be 999.99");
        

        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        double tamperedPrice = 1.00;
        js.executeScript("arguments[0].textContent = '" + tamperedPrice + "';", totalElement);
        WebElement clientTotalInput = driver.findElement(By.name("clientTotal"));
        js.executeScript("arguments[0].value = '" + tamperedPrice + "';", clientTotalInput);
        

        
        String tamperedTotalText = totalElement.getText();
        Assert.assertEquals(tamperedTotalText, "1.0", "DOM should reflect tampered price");


        
        driver.findElement(By.name("cardNumber")).sendKeys("4532123456789012");
        driver.findElement(By.name("cardName")).sendKeys("Test Tamper");
        driver.findElement(By.name("expiryDate")).sendKeys("12/25");
        driver.findElement(By.name("cvv")).sendKeys("123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        

        
        wait.until(d -> d.getPageSource().contains("Order Confirmed!") ||
                        d.getPageSource().contains("Payment processing failed") ||
                        d.getPageSource().contains("Invalid card number"));


        String currentUrl = driver.getCurrentUrl();
        boolean hasConfirmation = currentUrl.contains("/confirmation") ||
                                  driver.getPageSource().contains("Order Confirmed!");
        Assert.assertTrue(hasConfirmation,
            "Checkout should render confirmation on successful (and secure) payment. Current URL: " + currentUrl);
        

        
        boolean hasErrorMessage = driver.getPageSource().contains("Price mismatch") ||
                                 driver.getPageSource().contains("Invalid amount") ||
                                 driver.getPageSource().contains("Payment failed");
        
        Assert.assertFalse(hasErrorMessage, 
            "Server should not produce an error; it should process the correct price.");


        
        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("Order Confirmed!"), "Confirmation page should show success");
        assertSecurityEventLogged("AMOUNT_TAMPERING");

    }
    
    @Test(priority = 2, description = "Test negative amount submission")
    public void testNegativeAmountSubmission() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        clearCartIfNeeded(wait);
        addPremiumLaptopToCart(wait);

        navigateToUrl("/cart");
        String cartItemId = getCartItemId();
        String csrfToken = getCsrfTokenFromCart();

        Response response = postCartUpdate(cartItemId, "-1", csrfToken);
        Assert.assertNotEquals(response.statusCode(), 403,
            "CSRF validation failed when testing negative quantity submission");


        navigateToUrl("/cart");
        Assert.assertTrue(driver.getPageSource().contains("Your cart is empty"),
            "Cart should be empty after negative quantity update");

        assertSecurityEventLogged("AMOUNT_TAMPERING");

    }
    
    @Test(priority = 3, description = "Test decimal precision manipulation")
    public void testDecimalPrecisionAttack() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        clearCartIfNeeded(wait);
        addPremiumLaptopToCart(wait);

        navigateToUrl("/cart");
        String cartItemId = getCartItemId();
        String csrfToken = getCsrfTokenFromCart();
        String originalQuantity = getCartQuantity();

        Response response = postCartUpdate(cartItemId, "1.5", csrfToken);
        Assert.assertNotEquals(response.statusCode(), 403,
            "CSRF validation failed when testing decimal quantity submission");


        navigateToUrl("/cart");
        Assert.assertFalse(driver.getPageSource().contains("Your cart is empty"),
            "Cart should not accept fractional quantity updates");
        String updatedQuantity = getCartQuantity();
        Assert.assertEquals(updatedQuantity, originalQuantity,
            "Fractional quantity should not change the server-side cart quantity");

        assertSecurityEventLogged("AMOUNT_TAMPERING");

    }
    
    @Test(priority = 4, description = "Test currency conversion bypass")
    public void testCurrencyConversionBypass() {
        navigateToUrl("/products?currency=USD");


        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        WebElement priceCell = wait.until(
            ExpectedConditions.presenceOfElementLocated(By.xpath("//tr[contains(., 'Premium Laptop')]/td[4]")
        ));
        String priceText = priceCell.getText();
        Assert.assertTrue(priceText.contains("999.99"),
            "Currency query parameter should not alter server-side pricing (price: " + priceText + ")");


        assertSecurityEventLogged("AMOUNT_TAMPERING");

    }



    private void addPremiumLaptopToCart(WebDriverWait wait) {
        navigateToUrl("/products");
        WebElement laptopRow = wait.until(
            ExpectedConditions.presenceOfElementLocated(By.xpath("//tr[contains(., 'Premium Laptop')]")
        ));
        WebElement addToCartForm = laptopRow.findElement(By.tagName("form"));
        addToCartForm.findElement(By.tagName("button")).click();


        wait.until(ExpectedConditions.urlContains("/products"));
        navigateToUrl("/cart");
        Assert.assertFalse(driver.getPageSource().contains("Your cart is empty"),
            "Cart should contain Premium Laptop after add-to-cart");

    }



    private void clearCartIfNeeded(WebDriverWait wait) {
        navigateToUrl("/cart");
        if (!driver.getPageSource().contains("Your cart is empty")) {
            WebElement clearButton = wait.until(
                ExpectedConditions.elementToBeClickable(By.xpath("//form[@action='/cart/clear']//button")
            ));
            clearButton.click();
            wait.until(d -> d.getPageSource().contains("Your cart is empty"));
        }
    }



    private String getCartItemId() {
        WebElement removeForm = driver.findElement(By.cssSelector("form[action='/cart/remove']"));
        return removeForm.findElement(By.name("cartItemId")).getAttribute("value");
    }



    private String getCartQuantity() {
        WebElement quantityCell = driver.findElement(By.xpath("//tr[td]/td[3]"));
        return quantityCell.getText().trim();
    }



    private String getCsrfTokenFromCart() {
        WebElement csrfInput = driver.findElement(By.cssSelector("input[name='_csrf']"));
        return csrfInput.getAttribute("value");
    }



    private Response postCartUpdate(String cartItemId, String quantity, String csrfToken) {
        RestAssured.baseURI = baseUrl;
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        Cookie csrfCookie = driver.manage().getCookieNamed("XSRF-TOKEN");


        Assert.assertNotNull(sessionCookie, "Expected JSESSIONID cookie for cart update");
        Assert.assertNotNull(csrfCookie, "Expected XSRF-TOKEN cookie for cart update");


        return RestAssured.given()
            .redirects().follow(false)
            .cookie("JSESSIONID", sessionCookie.getValue())
            .cookie("XSRF-TOKEN", csrfCookie.getValue())
            .header("X-XSRF-TOKEN", csrfCookie.getValue())
            .formParam("_csrf", csrfToken)
            .formParam("cartItemId", cartItemId)
            .formParam("quantity", quantity)
            .post("/cart/update");
    }

}
