package com.security.tests.payment;
import com.security.tests.base.BaseTest;
import org.testng.annotations.Test;

public class NegativeAmountTest extends BaseTest {
    @Test(description = "Test negative amount submission")
    public void testNegativeAmount() {
        navigateToUrl("/checkout");
        double negativeAmount = -100.00;
        boolean accepted = submitPayment(negativeAmount);
        eventLogger.logSecurityEvent(
            com.security.tests.utils.SecurityEvent.createHighSeverityEvent(
                "NEGATIVE_AMOUNT_TEST",
                "test_user",
                "negative_amount_submission",
                "Submitted negative amount: " + negativeAmount + ", accepted: " + accepted
            )
        );
        org.testng.Assert.assertFalse(accepted, "Negative payment amounts should not be accepted");
    }

    // Stub: Simulate payment submission
    private boolean submitPayment(double amount) {
        // TODO: Implement actual payment logic or mock
        return false;
    }
}
