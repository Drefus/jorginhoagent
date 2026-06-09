// Arquivo de teste com vulnerabilidades Java
import java.sql.*;
import java.io.*;
import java.security.MessageDigest;

public class VulnJava {

    // SQL Injection
    public ResultSet getUser(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "password123");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = " + userId;
        return stmt.executeQuery(query);
    }

    // Command Injection
    public String runCommand(String userInput) throws IOException {
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("cmd /c " + userInput);
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        return reader.readLine();
    }

    // Weak Cryptography
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Hardcoded credentials
    private static final String DB_PASSWORD = "super_secret_123";
    private static final String API_KEY = "AKIAIOSFODNN7EXAMPLE";

    // Path Traversal
    public String readFile(String filename) throws IOException {
        File file = new File("/data/" + filename);
        BufferedReader br = new BufferedReader(new FileReader(file));
        return br.readLine();
    }

    // Insecure deserialization
    public Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
