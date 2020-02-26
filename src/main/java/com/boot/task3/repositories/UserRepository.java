package com.boot.task3.repositories;

import com.boot.task3.entities.Roles;
import com.boot.task3.entities.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import javax.management.relation.Role;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {

    Optional<Users> findById(Long id);
    Users findByEmail(String email);
    List<Users> findAllByRolesIsNotContainingAndRolesIsNotContaining(Roles role1, Roles role2);
    List<Users> findAllByRolesIsNotContaining(Roles role);

}
