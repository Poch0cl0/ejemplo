package com.ejemplo.ejemplo.persona;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;
@Service
@RequiredArgsConstructor
public class personaservicio {
 private final personarepositorio personarepo;
 public void creapersona(persona person)
 {
 personarepo.save(person);
 }
}