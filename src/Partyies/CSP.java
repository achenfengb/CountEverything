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
import network.Server;
import network.communicateData;
import thep.paillier.PrivateKey;

/**
 *
 * @author cf
 */
public class CSP implements Runnable{
    int listening_port;
    int parties_num;
    int numOfThreads;
    int numofBits;
    
    int[] results;

    public CSP(int listening_port, int parties_num, int numOfThreads, int numofBits) {
        this.listening_port = listening_port;
        this.parties_num = parties_num;
        this.numOfThreads = numOfThreads;
        this.numofBits = numofBits;
    }
    
    @Override
    public void run(){
        Server server = new Server();
        HMEOperations.thread_num = this.numOfThreads;
        PrivateKey pr_key = new PrivateKey(this.numofBits);
        
        try {
            for (int n = 0; n < this.parties_num + 1; n++) {
                server.listen(this.listening_port);
                server.getOos().writeObject(pr_key.getPublicKey());
                server.getOos().flush();
                server.disconnect();
            }
            
            server.listen(this.listening_port);
            BigInteger[] enc_bi = communicateData.readBIVector(server.getOis());
            results = new int[enc_bi.length];
            long t0 = System.currentTimeMillis();
            BigInteger[] results_bi = HMEOperations.decrypt(enc_bi, pr_key);
            System.out.println("The running time of decryption is " + (System.currentTimeMillis() - t0) / 1e3);
            
            int numOfResults = 0;
            
            for(int m = 0; m < results_bi.length; m++){
                 
                if(results_bi[m].compareTo(BigInteger.ZERO)==0){
                    results[m] = 1;
                    numOfResults++;
                }else{
                    results[m] = 0;
                }
            }
            
//            for(BigInteger bi_tmp : results_bi){
//                if(bi_tmp.compareTo(BigInteger.ZERO) == 0){
//                    numOfResults++;
//                }
//            }
            
            System.out.println("The number of matched records is " + numOfResults);
            server.disconnect();
        } catch (IOException | InterruptedException | ExecutionException ex) {
            Logger.getLogger(CSP.class.getName()).log(Level.SEVERE, null, ex);
        }
    
    }

    public int[] getResults() {
        return results;
    }
 
}
