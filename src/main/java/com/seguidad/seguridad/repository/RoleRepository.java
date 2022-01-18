package com.seguidad.seguridad.repository;

import com.seguidad.seguridad.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role,Integer> {
    Role getRoleById(int id);
    Role findByName(String name);
}
