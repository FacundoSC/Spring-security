package com.seguidad.seguridad.service;

import com.seguidad.seguridad.entity.Role;
import com.seguidad.seguridad.entity.Usuario;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;

public interface UsuarioService  extends UserDetailsService {

    Usuario getUser(int id);

    Usuario save(Usuario user);

    List<Usuario> findAll();
    Role saveRole(Role role);

    void addRoleToUser(String username , String rolename);
}
