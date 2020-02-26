package com.boot.task3.repositories;

import com.boot.task3.entities.Roles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RoleRepository extends JpaRepository<Roles, Long> {

    List<Roles> getRolesByIdIsNot(Long id);

}
