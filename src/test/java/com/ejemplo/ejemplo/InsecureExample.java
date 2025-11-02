import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class InsecureExample {
    public static void main(String[] args) throws Exception {
        String jdbcUrl = "jdbc:postgresql://localhost:5432/app";
        String dbUser = "postgres";
        String dbPass = "password123"; // HARD-CODE: mala práctica

        Connection conn = DriverManager.getConnection(jdbcUrl, dbUser, dbPass);
        Statement st = conn.createStatement();

        // Entrada sin validar: vulnerable a SQL injection
        String username = args.length > 0 ? args[0] : "admin'; --";
        String sql = "SELECT password FROM users WHERE username = '" + username + "'";

        ResultSet rs = st.executeQuery(sql);
        if (rs.next()) {
            String stored = rs.getString("password"); // contraseña en texto plano
            System.out.println("Stored password: " + stored);
        } else {
            System.out.println("Usuario no encontrado");
        }

        // No se cierran recursos correctamente en todas las rutas
        rs.close();
        st.close();
        conn.close();
    }
}
