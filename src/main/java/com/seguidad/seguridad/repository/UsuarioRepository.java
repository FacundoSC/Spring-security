package com.seguidad.seguridad.repository;

import com.seguidad.seguridad.entity.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario,Integer> {
    Usuario findByName(String name);

    Usuario findById(long id);

    List<Usuario> findAll();
}
