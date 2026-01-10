package com.security.tests.business;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

import java.time.Duration;

public class CartManipulationTest extends BaseTest {
    
    @Test(description = "Test cart price tampering")
    public void testCartPriceTampering() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        clearCartIfNeeded(wait);

        navigateToUrl("/products");
        WebElement productRow = wait.until(
            ExpectedConditions.presenceOfElementLocated(By.xpath("//tr[contains(., 'Premium Laptop')]")
        ));
        WebElement addToCartForm = productRow.findElement(By.tagName("form"));
        ((JavascriptExecutor) driver).executeScript(
            "var input = document.createElement('input');" +
            "input.type = 'hidden'; input.name = 'price'; input.value = '1.00';" +
            "arguments[0].appendChild(input);", addToCartForm
        );
        addToCartForm.findElement(By.tagName("button")).click();

        navigateToUrl("/cart");
        WebElement totalElement = wait.until(
            ExpectedConditions.presenceOfElementLocated(By.xpath("//div[@class='total']/span")
        ));
        String totalText = totalElement.getText();
        assertTrue(totalText.contains("999.99"),
            "Cart total should reflect server-side price, not tampered client input");

        assertSecurityEventLogged("CART_MANIPULATION");

    }
    
    @Test(description = "Test cart quantity manipulation")
    public void testQuantityManipulation() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        clearCartIfNeeded(wait);

        navigateToUrl("/products");
        WebElement productRow = wait.until(
            ExpectedConditions.presenceOfElementLocated(By.xpath("//tr[contains(., 'Premium Laptop')]")
        ));
        WebElement addToCartForm = productRow.findElement(By.tagName("form"));
        WebElement quantityInput = addToCartForm.findElement(By.name("quantity"));
        quantityInput.clear();
        quantityInput.sendKeys("0");
        ((JavascriptExecutor) driver).executeScript("arguments[0].submit();", addToCartForm);

        navigateToUrl("/cart");
        boolean emptyCart = driver.getPageSource().contains("Your cart is empty");
        assertTrue(emptyCart, "Cart should remain empty when quantity is zero");

        assertSecurityEventLogged("CART_MANIPULATION");

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

}
