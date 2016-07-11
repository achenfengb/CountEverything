/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package network;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author cf
 */
public class Server {

    protected ObjectInputStream ois;
    protected ObjectOutputStream oos;

    ServerSocket server_socket;
    Socket socket;

    /**
     * listen a given port
     *
     * @param port the port
     */
    public void listen(int port) {
        try {
            this.server_socket = new ServerSocket(port);
            this.socket = this.server_socket.accept();

            this.ois = new ObjectInputStream(this.socket.getInputStream());
            this.oos = new ObjectOutputStream(this.socket.getOutputStream());
        } catch (Exception e) {
            System.out.println("Server set up failed! :-)");
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
            if (this.server_socket != null) {
                this.server_socket.close();
            }
        } catch (IOException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
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
