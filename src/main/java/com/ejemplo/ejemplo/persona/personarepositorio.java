package com.ejemplo.ejemplo.persona;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
@Repository
public interface personarepositorio extends JpaRepository<persona,Integer>{
}