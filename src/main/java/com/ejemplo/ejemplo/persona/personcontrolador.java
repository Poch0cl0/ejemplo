package com.ejemplo.ejemplo.persona;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.RequiredArgsConstructor;
@RestController
@RequestMapping("/persona")
@RequiredArgsConstructor
public class personcontrolador {
 private final personaservicio personService;
 @PostMapping
 public void createPersona(@RequestBody persona person) {
 personService.creapersona(person);
 }
}