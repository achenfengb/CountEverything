/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package network;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author cf
 */
public class communicateData {
    public static byte[] readBytes(InputStream is, int len) throws IOException{
        byte[] temp = new byte[len];
        int remain = len;
        while(0 < remain){
            int readBytes = is.read(temp, len - remain, remain);
            if(readBytes != -1){
                remain -= readBytes;
            }
        }
        return temp;
    }
    
    public static byte[] readBytes(InputStream is) throws IOException{
        byte[] lenBytes = readBytes(is, 4);
        int len = ByteBuffer.wrap(lenBytes).getInt();
        return readBytes(is, len);
    }
    
    public static void writeBytes(OutputStream os, byte[] data) throws IOException{
        os.write(ByteBuffer.allocate(4).putInt(data.length).array());
        os.write(data);
    }
    
    public static int readInt(InputStream is) throws IOException {
        byte[] lenBytes = readBytes(is, 4);
        return ByteBuffer.wrap(lenBytes).getInt();
    }

    public static void writeInt(OutputStream os, int data) throws IOException {
        os.write(ByteBuffer.allocate(4).putInt(data).array());
    }
    
    public static int[] readIntVec(InputStream is) {
        int[] ret_int = null;
        try {
            int len = readInt(is);
            ret_int = new int[len];
            for (int n = 0; n < ret_int.length; n++) {
                ret_int[n] = ByteBuffer.wrap(readBytes(is, 4)).getInt();
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }
  
        return ret_int;
    }
    

    public static void writeIntVec(OutputStream os, int[] data) {
        try {
            writeInt(os, data.length);
            for(int n = 0; n < data.length; n++){
                os.write(ByteBuffer.allocate(4).putInt(data[n]).array());
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }
   
    }
    
    public static int[][] readIntMat(InputStream is) {
        int[][] ret_int = null;
        try {   
            int len = readInt(is);
            ret_int = new int[len][];
            for (int n = 0; n < ret_int.length; n++) {
                ret_int[n] = readIntVec(is);
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }

        return ret_int;
    }

    public static void writeIntMat(OutputStream os, int[][] data) {
        try {
            writeInt(os, data.length);
            for (int[] data1 : data) {
                writeIntVec(os, data1);
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static String readStr(InputStream is) throws IOException{
        byte[] ret_str = readBytes(is);
        return new String(ret_str);
    }
    
    public static void writeStr(OutputStream os, String str) throws IOException{
        writeBytes(os, str.getBytes());
    }    
    
    public static String[] readStrVector(InputStream is) {
        String[] ret_Strs = null;
        try {
            byte[] lenBytes = readBytes(is);
            int len = ByteBuffer.wrap(lenBytes).getInt();
            ret_Strs = new String[len];

            for (int n = 0; n < len; n++) {
                ret_Strs[n] = readStr(is);
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }

        return ret_Strs;
    }
    
    public static void writeStrVector(OutputStream os, String[] strs){
        try {
            writeBytes(os, ByteBuffer.allocate(4).putInt(strs.length).array());
            
            for (String str : strs) {
                writeStr(os, str);
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }    
    
    
    public static BigInteger readBI(InputStream is){
        byte[] rep = null;
        
        try {
            rep = readBytes(is);
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return (rep == null)?BigInteger.ZERO:new BigInteger(rep);
    }
    
    public static void writeBI(OutputStream os, BigInteger bi){
        try {
            writeBytes(os, bi.toByteArray());
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static BigInteger[] readBIVector(InputStream is){
        BigInteger[] ret_BIs = null;
        try {
            byte[] lenBytes = readBytes(is);
            int len = ByteBuffer.wrap(lenBytes).getInt();
            ret_BIs = new BigInteger[len];
            
            for(int n = 0; n < len; n++){
                ret_BIs[n] = readBI(is);
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return ret_BIs;
    }
    
    public static void writeBIVector(OutputStream os, BigInteger[] BIs){
        try {
            writeBytes(os,ByteBuffer.allocate(4).putInt(BIs.length).array());
            
            for (BigInteger BI : BIs) {
                writeBI(os, BI);
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    public static BigInteger[][] readBIMatrix(InputStream is) {
        BigInteger[][] ret_BIs = null;
        try {
            byte[] lenBytes = readBytes(is);
            int len = ByteBuffer.wrap(lenBytes).getInt();
            ret_BIs = new BigInteger[len][];

            for (int n = 0; n < len; n++) {
                ret_BIs[n] = readBIVector(is);
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }

        return ret_BIs;
    }
    
    public static void writeBIMatrix(OutputStream os, BigInteger[][] BIs){
        try {
            writeBytes(os, ByteBuffer.allocate(4).putInt(BIs.length).array());
            
            for (BigInteger[] BI : BIs) {
                writeBIVector(os, BI);
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    public static BigInteger[][][] readBIMatrix3D(InputStream is) {
        BigInteger[][][] ret_BIs = null;
        try {
            byte[] lenBytes = readBytes(is);
            int len = ByteBuffer.wrap(lenBytes).getInt();
            ret_BIs = new BigInteger[len][][];

            for (int n = 0; n < len; n++) {
                ret_BIs[n] = readBIMatrix(is);
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }

        return ret_BIs;
    }
    
    public static void writeBIMatrix3D(OutputStream os, BigInteger[][][] BIs) {
        try {
            writeBytes(os, ByteBuffer.allocate(4).putInt(BIs.length).array());

            for (BigInteger[][] BI : BIs) {
                writeBIMatrix(os, BI);
            }
        } catch (IOException ex) {
            Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    
//    public static void main(String[] args) throws InterruptedException {
//        
//        Thread th1 = new Thread(() -> {
//            Client clt1 = new Client();
//            try {
//                clt1.connect("localhost", 9000);
//                BigInteger[] abc = new BigInteger[]{new BigInteger("1233"), new BigInteger("324235"), new BigInteger("354535")};
//                writeBIVector(clt1.getOos(), abc);
//                clt1.oos.flush();
//                clt1.disconnect();
//            }catch (InterruptedException | IOException ex) {
//                Logger.getLogger(communicateData.class.getName()).log(Level.SEVERE, null, ex);
//            }
//        });
//
//       Thread th2 =  new Thread(() -> {
//            Server srr = new Server();
//            srr.listen(9000);
//            BigInteger[] abc = null;
//            abc = readBIVector(srr.getOis());
//            System.out.println(Arrays.toString(abc));
//            srr.disconnect();
//        });
//       
//       th1.start();
//       th2.start();
//       
//       th1.join();
//       th2.join();
//    }
}
