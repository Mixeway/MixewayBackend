package io.mixeway.integrations.infrastructurescan.plugin.openvas.apiclient;

import io.mixeway.db.entity.Scanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URI;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class OpenVasSocketHelper {
    private final static Logger log = LoggerFactory.getLogger(OpenVasSocketHelper.class);

    /** The url. */
    private URI mUrl;
    /** The socket. */
    private Socket mSocket;

    /** Whether the handshake is complete. */
    private boolean mHandshakeComplete;

    /** The socket input stream. */
    private InputStream mInput;

    /** The socket mOutput stream. */
    private OutputStream mOutput;


    /**
     * Creates a new WebSocket targeting the specified URL.
     * @param url The URL for the socket.
     */
    public OpenVasSocketHelper(URI url) {
        mUrl = url;

        //String protocol = mUrl.getScheme();
    }

    /**
     * Returns the underlying socket;
     */
    public Socket getSocket() {
        return mSocket;
    }

    /**
     * Establishes the connection.
     */
    public void connect() throws java.io.IOException, KeyManagementException, NoSuchAlgorithmException {
        mSocket = createSocket();
        if (mSocket != null) {

            mOutput = mSocket.getOutputStream();
            mInput = mSocket.getInputStream();


            mHandshakeComplete = true;
        } else {
            mHandshakeComplete = false;
        }
    }

    private Socket createSocket() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }};

// Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());

        SSLSocketFactory sslsocketfactory = sc.getSocketFactory();
        SocketFactory factory = sslsocketfactory.getDefault();
        try {
            return factory.createSocket(mUrl.getHost(), mUrl.getPort());
        } catch (IOException ce){
            return null;
        }

    }

    /**
     * Sends the specified string as a data frame.
     * @param str The string to send.
     * @throws java.io.IOException
     */
    public void send(String str) throws java.io.IOException {
        if (!mHandshakeComplete) {
            throw new IllegalStateException("Handshake not complete");
        }

        //mOutput.write(0x00);
        mOutput.write(str.getBytes());
        mOutput.write(0xff);
        mOutput.flush();
    }

    /**
     * Receives the next data frame.
     * @return The received data.
     * @throws java.io.IOException
     */
    public String recv() throws java.io.IOException {
//        int nRead;
//        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
//        byte[] data = new byte[10240];
//        while ((nRead = mInput.read(data, 0, data.length)) != -1) {
//            buffer.write(data, 0, nRead);
//        }
//
//        buffer.flush();
//        byte[] byteArray = buffer.toByteArray();
        byte[] messageByte = new byte[10000];
        boolean end = false;
        String dataString = "";
        DataInputStream in = new DataInputStream(mInput);
        int bytesRead = 0;

        messageByte[0] = in.readByte();
        messageByte[1] = in.readByte();
        ByteBuffer byteBuffer = ByteBuffer.wrap(messageByte, 0, 2);

        int bytesToRead = byteBuffer.getShort();
        System.out.println("About to read " + bytesToRead + " octets");

        //The following code shows in detail how to read from a TCP socket

        while(!end)
        {
            bytesRead = in.read(messageByte);
            dataString += new String(messageByte, 0, bytesRead);
            if (dataString.length() == bytesToRead )
            {
                end = true;
            }
        }

        //All the code in the loop can be replaced by these two lines
        //in.readFully(messageByte, 0, bytesToRead);
        //dataString = new String(messageByte, 0, bytesToRead);

        System.out.println("MESSAGE: " + dataString);
        //String text = new String(dataString, StandardCharsets.UTF_8);
        return dataString;
    }

    /**
     * Closes the socket.
     * @throws java.io.IOException
     */
    public void close() throws java.io.IOException {
        mInput.close();
        mOutput.close();
        mSocket.close();
    }

    public static String processRequest(String request, Scanner scanner) {
        try {
            OpenVasSocketHelper ws = new OpenVasSocketHelper(new URI(scanner.getApiUrl().trim()));
            ws.connect();
            ws.send(request);
            String res = ws.recv();
            return res;

        } catch (Exception e) {
            log.error("Error during executing Socket {}",e.getLocalizedMessage());
            return null;
        }
    }
}




