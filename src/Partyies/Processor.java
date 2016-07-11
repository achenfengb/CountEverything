/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Partyies;

import HME.HMEOperations;
import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import network.Client;
import network.Server;
import network.communicateData;
import thep.paillier.PublicKey;

/**
 *
 * @author cf
 */
public class Processor implements Runnable{
    String CSP_addr;
    int CSP_port;
    int listening_port;
    int parties_num = 1;
    int numOfThreads = 1;

    public Processor(String CSP_addr, int CSP_port, int listening_port, int parties_num, int numOfThreads) {
        this.CSP_addr = CSP_addr;
        this.CSP_port = CSP_port;
        this.listening_port = listening_port;
        this.parties_num = parties_num;
        this.numOfThreads = numOfThreads;
    }
    
    @Override
    public void run() {
        Client client = new Client();
        Server server = new Server();
        
        HMEOperations.thread_num = this.numOfThreads;
        BigInteger[][] enc_data = new BigInteger[this.parties_num][];
        BigInteger[] enc_sent_data;
        
        try {
            client.connect(CSP_addr, CSP_port);
            PublicKey pub_key = (PublicKey)client.getOis().readObject();
            client.disconnect();
            
            
            for(int n = 0; n < this.parties_num; n++){
                server.listen(this.listening_port);
                enc_data[n] = communicateData.readBIVector(server.getOis());
                server.disconnect();
            }
            
            long t0 = System.currentTimeMillis();
            enc_sent_data = enc_data[0];
            for(int n = 1; n < this.parties_num; n++){
                try {
                    enc_sent_data = HMEOperations.sum(enc_sent_data, enc_data[n], pub_key.getNSquared());
                } catch (ExecutionException ex) {
                    Logger.getLogger(Processor.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            System.out.println("The running time of summation is " + (System.currentTimeMillis() - t0)/1e3);
            
            client.connect(CSP_addr, CSP_port);
            communicateData.writeBIVector(client.getOos(), enc_sent_data);
            client.getOos().flush();
            client.disconnect();
            
        } catch (InterruptedException | IOException | ClassNotFoundException ex) {
            Logger.getLogger(Processor.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
}
