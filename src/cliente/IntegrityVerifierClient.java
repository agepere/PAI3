package cliente;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import javax.swing.*;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import utils.*;

public class IntegrityVerifierClient {
    // Constructor que abre una conexión Socket para enviar mensaje/MAC al servidor
    public IntegrityVerifierClient() {
        try {
            SocketFactory socketFactory = (SocketFactory) SocketFactory.getDefault();
            Socket socket = (Socket) socketFactory.createSocket("localhost", 7070);
            
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(Utils.getKey());
            
            // Crea un PrintWriter para enviar mensaje/MAC al servidor
            PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            String message = JOptionPane.showInputDialog(null, "Introduzca su mensaje:");
            // Envío del mensaje al servidor
            output.println(message);
            String offset = Utils.getOffset();
            if (offset == "" || offset==null) {
            	offset = "1";
            }
            output.println(offset);
            StringBuilder sb= new StringBuilder();
            sb.append(message);
            sb.append(offset);
            mac.update((sb.toString()).getBytes("UTF-8"));
            // Habría que calcular el correspondiente MAC con la clave compartida por servidor/cliente
            byte[] macByte = mac.doFinal();
            output.println(Utils.encodeHexString(macByte));
            // Importante para que el mensaje se envíe
            output.flush();
            // Crea un objeto BufferedReader para leer la respuesta del servidor
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            // Lee la respuesta del servidor
            String respuesta = input.readLine();
            // Muestra la respuesta al cliente
            JOptionPane.showMessageDialog(null, respuesta);
            Utils.setOffset(new Integer(offset)+1);
            // Se cierra la conexion
            output.close();
            input.close();
            socket.close();
        } // end try
        catch (IOException | NoSuchAlgorithmException | InvalidKeyException ioException) {
            ioException.printStackTrace();
        }
        // Salida de la aplicacion
        finally {
            System.exit(0);
        }
    }
}