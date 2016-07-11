/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Partyies;

import HME.HMEOperations;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import network.Client;
import network.communicateData;
import thep.paillier.PublicKey;

/**
 *
 * @author cf
 */
public class DataOwner implements Runnable{
    String CSP_addr;
    String Server_addr;
    int CSP_port;
    int Server_port;
    
    int[] IDs;
    int numOfBits;
    
    int numOfThreads = 1;
    
    static Random rnd = new Random();

    public DataOwner(String CSP_addr, String Server_addr, int CSP_port, int Server_port, int[] IDs, int numOfBits, int numOfThreads) {
        this.CSP_addr = CSP_addr;
        this.Server_addr = Server_addr;
        this.CSP_port = CSP_port;
        this.Server_port = Server_port;
        this.IDs = IDs;
        this.numOfBits = numOfBits;
        this.numOfThreads = numOfThreads;
    }

    
    @Override
    public void run(){
        Client client = new Client();
        HMEOperations.thread_num = this.numOfThreads;
        
        try {
            BigInteger[] bi_data = new BigInteger[this.IDs.length];
            client.connect(CSP_addr, CSP_port);
            PublicKey pub_key = (PublicKey)client.getOis().readObject();
            client.disconnect();
            int bits = pub_key.getBits();
            
//            BigInteger g = communicateData.readBI(client.getOis());
//            BigInteger NSqaured = communicateData.readBI(client.getOis());
            
            for(int n = 0; n < bi_data.length; n++){
                if(IDs[n] > 0){
                    bi_data[n] = BigInteger.ZERO;
                }else{
                    bi_data[n] = new BigInteger(bits, rnd);
                }
            }
            
            long t0 = System.currentTimeMillis();
            BigInteger[] enc_bi = HMEOperations.encrypt1(bi_data, pub_key);
            System.out.println("The running time of encryption is " + (System.currentTimeMillis() - t0)/1e3);
            client.connect(Server_addr, Server_port);
            communicateData.writeBIVector(client.getOos(), enc_bi);
            client.getOos().flush();
            client.disconnect();

        } catch (InterruptedException | IOException | ClassNotFoundException | ExecutionException ex) {
            Logger.getLogger(DataOwner.class.getName()).log(Level.SEVERE, null, ex);
        }
               
    }
}
