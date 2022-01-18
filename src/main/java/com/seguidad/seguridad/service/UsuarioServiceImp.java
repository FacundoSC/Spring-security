package com.seguidad.seguridad.service;

import com.seguidad.seguridad.entity.Role;
import com.seguidad.seguridad.entity.Usuario;
import com.seguidad.seguridad.mapper.UserDetailsMapper;
import com.seguidad.seguridad.repository.RoleRepository;
import com.seguidad.seguridad.repository.UsuarioRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;


@Service("userDetailsService")@Slf4j
public class UsuarioServiceImp implements UsuarioService{

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UsuarioRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final Usuario retrievedUser = userRepository.findByName(username);
        if (retrievedUser == null) {
            log.info("el usuario {} no se encuentra  registrado",username);

            throw new UsernameNotFoundException("Invalid username or password");
        }
      //  return UserDetailsMapper.build(retrievedUser);


        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

        retrievedUser.getRoles().forEach(role -> {
            authorities.add( new SimpleGrantedAuthority(role.getName()));
        });

        //hace la importacion  porque  la clase user esta dos  veces una definida por nosotros y otra por el package details
        return new User(retrievedUser.getName(),retrievedUser.getPassword(),authorities);

    }

    @Override
    public Usuario getUser(int id) {
     return userRepository.findById(id);
    }

    @Override
    public Usuario save(Usuario user) {
        Role userRole = roleRepository.findByName("USER");
        Set<Role> roles = new HashSet<>();
        roles.add(userRole);

        Usuario userToSave = Usuario.builder()
                .name(user.getName())
                .password(user.getPassword())
                .roles(roles)
                .build();
        return userRepository.save(userToSave);
    }

    @Override
    public List<Usuario> findAll() {
        return userRepository.findAll();
    }

    @Override
    public Role saveRole(Role role) {
        log.info("guardando un nuevo rol {} en la base  de datos", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String rolename) {
        Usuario user = userRepository.findByName(username);
        Role role = roleRepository.findByName(rolename);
        user.getRoles().add(role);
        userRepository.save(user);
    }


}
