package com.security.ecommerce.repository;

import com.security.ecommerce.model.CartItem;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CartItemRepository extends JpaRepository<CartItem, Long> {

    List<CartItem> findBySessionId(String sessionId);

    // pessimistic write lock prevents concurrent updates from corrupting quantity
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM CartItem c WHERE c.id = :id")
    Optional<CartItem> findByIdWithLock(@Param("id") Long id);

    // row-level lock on all items in a session during checkout
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM CartItem c WHERE c.sessionId = :sessionId")
    List<CartItem> findBySessionIdWithLock(@Param("sessionId") String sessionId);

    void deleteBySessionId(String sessionId);
}
