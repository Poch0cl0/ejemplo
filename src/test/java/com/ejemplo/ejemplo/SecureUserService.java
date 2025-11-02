import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.Base64;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * SecureUserService - ejemplo de operaciones seguras: crear usuario, autenticar usuario, escribir archivo seguro.
 *
 * Notas de seguridad:
 * - No hardcodear credenciales: usar variables de entorno o un vault.
 * - Usar un usuario de BD con permisos mínimos (solo INSERT/SELECT en la tabla de usuarios).
 * - Asegurar canal (TLS) y configuración del servidor DB.
 * - Evitar exponer excepciones detalladas al cliente.
 */
public final class SecureUserService {
    private static final Logger LOGGER = Logger.getLogger(SecureUserService.class.getName());

    // PBKDF2 parameters razonables (pueden ajustarse según HW)
    private static final String PBKDF2_ALGO = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32; // 256 bits
    private static final int PBKDF2_ITERATIONS = 100_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    // Ejemplo simple de validación de username/email (no cubrirá todos los casos)
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]{3,30}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]{2,}$");

    // Evitar construir Strings con datos sensibles para logs
    private final String jdbcUrl;
    private final String dbUser;
    private final String dbPassword; // preferible usar vault o provider de secretos

    public SecureUserService(String jdbcUrl, String dbUser, String dbPassword) {
        this.jdbcUrl = jdbcUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
    }

    // ----------------------------
    // Hashing seguro (PBKDF2)
    // ----------------------------
    private static String hashPassword(char[] password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, HASH_BYTES * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGO);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            // Guardar como iterations:salt:hash en Base64
            return PBKDF2_ITERATIONS + ":" + Base64.getEncoder().encodeToString(salt) + ":" +
                    Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // No exponer detalles en producción
            LOGGER.log(Level.SEVERE, "Error interno de hashing", e);
            throw new RuntimeException("Error interno de seguridad");
        }
    }

    private static boolean verifyPassword(char[] password, String stored) {
        try {
            String[] parts = stored.split(":");
            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[2]);

            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, expectedHash.length * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGO);
            byte[] actualHash = skf.generateSecret(spec).getEncoded();

            // Comparación en tiempo constante
            return MessageDigest.isEqual(expectedHash, actualHash);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Verificación de contraseña falló", e);
            return false;
        }
    }

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return salt;
    }

    // ----------------------------
    // Operaciones de DB seguras
    // ----------------------------

    /**
     * Crea la tabla usuarios si no existe. Debe ejecutarse con un usuario que tenga permiso de CREATE (o crearla manualmente).
     * En producción, crear la tabla con migraciones y no permitir DDL desde la app.
     */
    public void ensureUsersTable() {
        String sql = "CREATE TABLE IF NOT EXISTS users (" +
                "id SERIAL PRIMARY KEY," +
                "username VARCHAR(100) UNIQUE NOT NULL," +
                "email VARCHAR(255) UNIQUE NOT NULL," +
                "password_hash TEXT NOT NULL," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                ")";
        try (Connection conn = getConnection();
             Statement st = conn.createStatement()) {
            st.execute(sql);
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "No se pudo asegurar la tabla de usuarios", e);
            // No exponer detalles a cliente
        }
    }

    /**
     * Crea usuario de forma segura (validación + prepared statement).
     */
    public boolean createUser(String username, String email, char[] password) {
        if (!isValidUsername(username) || !isValidEmail(email) || password == null || password.length < 8) {
            return false; // validar inputs y longitud mínima de contraseña
        }

        byte[] salt = generateSalt();
        String hash = hashPassword(password, salt);

        String sql = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, email);
            ps.setString(3, hash);
            ps.executeUpdate();
            return true;
        } catch (SQLException e) {
            // Manejar errores sin revelar detalles
            LOGGER.log(Level.WARNING, "No se pudo crear usuario (posible duplicado o error de BD).", e);
            return false;
        } finally {
            // limpiar password char[] si es necesario
            wipeCharArray(password);
        }
    }

    /**
     * Autentica usuario consultando hash (prepared statement) y verificando el password localmente.
     */
    public boolean authenticate(String usernameOrEmail, char[] password) {
        if (usernameOrEmail == null || password == null) return false;

        String sql = "SELECT password_hash FROM users WHERE username = ? OR email = ?";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, usernameOrEmail);
            ps.setString(2, usernameOrEmail);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String stored = rs.getString("password_hash");
                    boolean ok = verifyPassword(password, stored);
                    wipeCharArray(password);
                    return ok;
                } else {
                    // Si no existe, hacer una verificación dummy para evitar user enumeration timing attacks
                    dummyHashVerification();
                    wipeCharArray(password);
                    return false;
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Error autenticando usuario", e);
            wipeCharArray(password);
            return false;
        }
    }

    // ----------------------------
    // Helpers y buenas prácticas
    // ----------------------------
    private Connection getConnection() throws SQLException {
        // Usar connection pool en producción (HikariCP, etc.)
        // No hardcodear password; usar variables de entorno o vault
        return DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
    }

    private static boolean isValidUsername(String u) {
        return u != null && USERNAME_PATTERN.matcher(u).matches();
    }

    private static boolean isValidEmail(String e) {
        return e != null && e.length() <= 254 && EMAIL_PATTERN.matcher(e).matches();
    }

    private static void wipeCharArray(char[] arr) {
        if (arr != null) {
            for (int i = 0; i < arr.length; i++) arr[i] = '\0';
        }
    }

    /**
     * Verificación dummy que crea un hash temporal para consumir tiempo similar al caso exitoso
     * y restringir posibilidad de medir tiempos para enumerar usuarios.
     */
    private static void dummyHashVerification() {
        char[] fake = "fakePassword".toCharArray();
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        try {
            hashPassword(fake, salt);
        } finally {
            wipeCharArray(fake);
        }
    }

    /**
     * Ejemplo simple de escribir archivo de forma segura (evita directory traversal).
     * NO escribe fuera del directorio base.
     */
    public boolean safeWriteFile(String baseDir, String relativePath, byte[] content) {
        // Validar path: no permitir ../
        if (relativePath.contains("..") || relativePath.startsWith("/") || relativePath.startsWith("\\")) {
            LOGGER.warning("Ruta inválida solicitada");
            return false;
        }
        java.nio.file.Path base = java.nio.file.Paths.get(baseDir).toAbsolutePath().normalize();
        java.nio.file.Path target = base.resolve(relativePath).normalize();
        if (!target.startsWith(base)) {
            LOGGER.warning("Intento de escape de directorio bloqueado");
            return false;
        }

        try {
            java.nio.file.Files.createDirectories(target.getParent());
            java.nio.file.Files.write(target, content, java.nio.file.StandardOpenOption.CREATE_NEW);
            return true;
        } catch (java.nio.file.FileAlreadyExistsException fae) {
            LOGGER.warning("El archivo ya existe");
            return false;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error al escribir archivo", e);
            return false;
        }
    }

    // ----------------------------
    // Ejemplo de uso rápido (main)
    // ----------------------------
    public static void main(String[] args) {
        // Obtener credenciales desde variables de entorno (NO hardcodear)
        String jdbcUrl = System.getenv("APP_JDBC_URL"); // p.ej. "jdbc:postgresql://db:5432/app"
        String dbUser = System.getenv("APP_DB_USER");
        String dbPass = System.getenv("APP_DB_PASS");

        if (jdbcUrl == null || dbUser == null || dbPass == null) {
            LOGGER.severe("Variables de entorno para BD no seteadas. Abortando.");
            return;
        }

        SecureUserService svc = new SecureUserService(jdbcUrl, dbUser, dbPass);

        // En producción NO ejecutar ensureUsersTable desde la app; usar migraciones
        svc.ensureUsersTable();

        // Demostración (no usar contraseñas en claro en args)
        String username = "usuario_demo";
        String email = "demo@example.com";
        char[] password = "Secr3tP@ss!".toCharArray();

        boolean created = svc.createUser(username, email, password);
        System.out.println("Usuario creado: " + created);

        // Autenticación
        char[] attempt = "Secr3tP@ss!".toCharArray();
        boolean authed = svc.authenticate("usuario_demo", attempt);
        System.out.println("Autenticación correcta: " + authed);
    }
}
