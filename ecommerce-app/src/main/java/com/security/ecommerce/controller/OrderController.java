package com.security.ecommerce.controller;

import com.security.ecommerce.model.Transaction;
import com.security.ecommerce.service.SecurityEventService;
import com.security.ecommerce.service.TransactionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/orders")
public class OrderController {

    private final TransactionService transactionService;
    private final SecurityEventService securityEventService;

    public OrderController(TransactionService transactionService,
                           SecurityEventService securityEventService) {
        this.transactionService = transactionService;
        this.securityEventService = securityEventService;
    }

    @GetMapping("/{id}")
    public ResponseEntity<OrderSummary> getOrder(@PathVariable Long id) {
        Transaction transaction = transactionService.getTransactionById(id);
        if (transaction == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication != null ? authentication.getName() : "anonymous";
        String owner = transaction.getUser() != null ? transaction.getUser().getUsername() : null;
        if (owner == null || !owner.equals(username)) {
            securityEventService.logHighSeverityEvent(
                "ACCESS_CONTROL_VIOLATION",
                username,
                "Order access blocked for non-owner",
                "orderId=" + id
            );
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        return ResponseEntity.ok(toSummary(transaction));
    }

    private OrderSummary toSummary(Transaction transaction) {
        return new OrderSummary(
            transaction.getId(),
            transaction.getTransactionId(),
            transaction.getAmount(),
            transaction.getStatus().name(),
            transaction.getTransactionDate()
        );
    }

    public record OrderSummary(
        Long id,
        String transactionId,
        java.math.BigDecimal amount,
        String status,
        java.time.LocalDateTime transactionDate
    ) {}
}
