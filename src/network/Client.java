/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package network;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author cf
 */
public class Client {

    protected ObjectInputStream ois;
    protected ObjectOutputStream oos;

    Socket socket;

    /**
     * try to connect with server
     *
     * @param server the server address
     * @param port the server port
     * @throws InterruptedException
     */
    public void connect(String server, int port) throws InterruptedException {
        while (true) {
            try {
                socket = new Socket(server, port);

                if (socket != null) {
                    oos = new ObjectOutputStream(socket.getOutputStream());
                    ois = new ObjectInputStream(socket.getInputStream());
                    break;
                }
            } catch (IOException e) {
                Thread.sleep(10);
            }
        }
    }

    /**
     * disconnect this connection
     */
    public void disconnect() {
        try {
            if (socket != null) {
                this.socket.close();
            }
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * get the input stream
     *
     * @return the input stream
     */
    public ObjectInputStream getOis() {
        return ois;
    }

    /**
     * get the output stream
     *
     * @return the output stream
     */
    public ObjectOutputStream getOos() {
        return oos;
    }

}
