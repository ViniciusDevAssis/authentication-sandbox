package com.viniciusdevassis.authentication.sandbox.infrastructure.repositories;

import com.viniciusdevassis.authentication.sandbox.domain.entities.Business;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface BusinessRepository extends JpaRepository<Business, UUID> {
}
