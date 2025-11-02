import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class SecureExample {
    private static final Logger LOGGER = Logger.getLogger(SecureExample.class.getName());
    private static final String PBKDF2_ALGO = "PBKDF2WithHmacSHA256";
    private static final int ITER = 100_000;
    private static final int HASH_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]{3,30}$");

    public static void main(String[] args) {
        String jdbcUrl = System.getenv("APP_JDBC_URL"); // ej. "jdbc:postgresql://db:5432/app"
        String dbUser = System.getenv("APP_DB_USER");
        String dbPass = System.getenv("APP_DB_PASS");
        if (jdbcUrl == null || dbUser == null || dbPass == null) {
            LOGGER.severe("Variables de entorno de BD no configuradas");
            return;
        }

        String username = args.length > 0 ? args[0] : "defaultUser";
        if (!isValidUsername(username)) {
            LOGGER.warning("username inválido");
            return;
        }

        // Consulta segura usando PreparedStatement
        String sql = "SELECT password_hash FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(jdbcUrl, dbUser, dbPass);
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String stored = rs.getString("password_hash");
                    // No revelar hash; sólo demostración de verificación
                    System.out.println("Usuario existe. (Hash protegido, no mostrado)");
                } else {
                    System.out.println("Usuario no encontrado");
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Error al acceder a BD", e);
        }
    }

    // Ejemplo de hashing PBKDF2 (para demostrar buena práctica)
    public static String hashPassword(char[] password) {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITER, HASH_BYTES * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGO);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return ITER + ":" + Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
        } catch (InvalidKeySpecException | java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    private static boolean isValidUsername(String u) {
        return u != null && USERNAME_PATTERN.matcher(u).matches();
    }
}