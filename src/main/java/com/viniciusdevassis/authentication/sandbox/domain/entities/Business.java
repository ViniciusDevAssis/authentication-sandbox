package com.viniciusdevassis.authentication.sandbox.domain.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "tb_businesses")
@NoArgsConstructor
@Getter
@Setter(AccessLevel.PRIVATE)
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class Business {

    @Id
    @EqualsAndHashCode.Include
    private UUID id;
    private String name;
    private String email;
}
