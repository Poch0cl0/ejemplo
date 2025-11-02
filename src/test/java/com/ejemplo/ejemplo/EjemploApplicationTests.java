import java.io.*;

public class VulnerableDeserializer {
    public static void main(String[] args) throws Exception {
        FileInputStream fileIn = new FileInputStream("payload.ser");
        ObjectInputStream in = new ObjectInputStream(fileIn);
        Object obj = in.readObject();
        Object obj = in.readObject(); // ⚠️ Peligroso si no se valida el tipo ni el origen
        in.close();
        fileIn.close();

        System.out.println("Objeto deserializado: " + obj);
    }

    public static void main(String[] args) throws Exception {
        FileInputStream fileIn = new FileInputStream("payload.ser");
        ObjectInputStream in = new ObjectInputStream(fileIn);
        Object obj = in.readObject();
        Object obj = in.readObject(); // ⚠️ Peligroso si no se valida el tipo ni el origen
        in.close();
        fileIn.close();

        System.out.println("Objeto deserializado: " + obj);
    }
}