package cliente;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class IntegrityVerifierClient {
    // Constructor que abre una conexión Socket para enviar mensaje/MAC al servidor

    public IntegrityVerifierClient() {
        try {
            SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", 7070);
            socket.setEnabledCipherSuites(new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "SSLv3"});

            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(this.getKey());

            // Crea un PrintWriter para enviar mensaje/MAC al servidor
            PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            String message = JOptionPane.showInputDialog(null, "Introduzca su mensaje:");
            // Envío del mensaje al servidor
            output.println(message);
            String offset = this.getOffset();
            if (offset == "" || offset == null) {
                offset = "1";
            }
            output.println(offset);
            StringBuilder sb = new StringBuilder();
            sb.append(message);
            sb.append(offset);
            mac.update((sb.toString()).getBytes("UTF-8"));
            // Habría que calcular el correspondiente MAC con la clave compartida por servidor/cliente
            byte[] macByte = mac.doFinal();
            output.println(this.encodeHexString(macByte));
            // Importante para que el mensaje se envíe
            output.flush();
            // Crea un objeto BufferedReader para leer la respuesta del servidor
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            // Lee la respuesta del servidor
            String respuesta = input.readLine();
            // Muestra la respuesta al cliente
            JOptionPane.showMessageDialog(null, respuesta);
            this.setOffset(new Integer(offset) + 1);
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

    public static void main(String args[]) {
        new IntegrityVerifierClient();
    }

    private SecretKey getKey() {
        FileReader fileReader;
        try {
            fileReader = new FileReader("key.txt");

            // Always wrap FileReader in BufferedReader.
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            String line = bufferedReader.readLine();
//	        JOptionPane.showMessageDialog(null, Arrays.toString(Utils.decodeHexString(line)));
            bufferedReader.close();

            return new SecretKeySpec(this.decodeHexString(line), "HmacSHA512");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if (digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: " + hexChar);
        }
        return digit;
    }

    private byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

    private String getOffset() {
        FileReader fileReader;
        try {
            File file = new File("offset.txt");
            file.createNewFile();

            fileReader = new FileReader("offset.txt");

            // Always wrap FileReader in BufferedReader.
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            String offset = bufferedReader.readLine();
            bufferedReader.close();
            return offset;
        } catch (IOException e) {
            System.err.println("Hubo un problema obteniendo los offsets.");
        }
        return null;
    }

    private Integer setOffset(Integer offset) {
        try {

            PrintWriter writer = new PrintWriter("offset.txt");
            writer.print(offset.toString());
            writer.close();
            return offset;
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    private String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    private String encodeHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }
}