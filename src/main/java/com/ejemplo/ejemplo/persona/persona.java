package com.ejemplo.ejemplo.persona;
import jakarta.persistence.Basic;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor

public class persona {
    @Id
    @GeneratedValue
    private Integer id;
    @Basic
    private String firstname;
    private String lastname;
    private String email;
}
