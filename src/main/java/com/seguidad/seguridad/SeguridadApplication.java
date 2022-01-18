package com.seguidad.seguridad;

import com.seguidad.seguridad.entity.Role;
import com.seguidad.seguridad.entity.Usuario;
import com.seguidad.seguridad.service.UsuarioService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SeguridadApplication {

	public static void main(String[] args) {
		SpringApplication.run(SeguridadApplication.class, args);
	}


/*
	@Bean
	CommandLineRunner run(UsuarioService userService){
		return args -> {

			userService.saveRole(new Role(0,"ROLE_USER"));
			userService.saveRole(new Role(0,"ROLE_MANAGER"));
			userService.saveRole(new Role(0,"ROLE_SUPERMANAGER"));


			userService.save(new Usuario(0,"user",encodering().encode("user"), null));
			userService.save(new Usuario(0,"admin",encodering().encode("admin"),null));
			userService.save(new Usuario(0,"superadmin",encodering().encode("superadmin"),null));


			userService.addRoleToUser("user","ROLE_USER");
			userService.addRoleToUser("admin","ROLE_MANAGER");
			userService.addRoleToUser("superadmin","ROLE_SUPERMANAGER");
		};
	}


*/

	@Bean
	public BCryptPasswordEncoder encodering() {
		return new BCryptPasswordEncoder();
	}





}
