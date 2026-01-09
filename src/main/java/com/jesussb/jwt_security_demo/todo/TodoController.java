package com.jesussb.jwt_security_demo.todo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/v1/todos")
public class TodoController {

    @GetMapping
    @PreAuthorize(value = "hasRole('ADMIN')")
    public ResponseEntity<String> todos() {
        return ResponseEntity.ok("Todos");
    }

    @GetMapping("/todos-unsecured")
    @PreAuthorize(value = "hasRole('USER')")
    public ResponseEntity<String> todosUnsecured() {
        return ResponseEntity.ok("Todos unsecured");
    }

}
