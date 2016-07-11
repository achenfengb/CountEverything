/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package HME;

import java.math.BigInteger;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import thep.paillier.EncryptedInteger;
import thep.paillier.PrivateKey;
import thep.paillier.PublicKey;

/**
 *
 * @author cf
 */
public class HMEOperations {
    public static int thread_num = 2;

    private final static class func_encryptInteger implements Callable<EncryptedInteger> {

        BigInteger bi;
        PublicKey pub_key;

        public func_encryptInteger(BigInteger bi, PublicKey pub_key) {
            this.bi = bi;
            this.pub_key = pub_key;
        }

        public func_encryptInteger(String bi, PublicKey pub_key) {
            this.bi = new BigInteger(bi);
            this.pub_key = pub_key;
        }

        @Override
        public EncryptedInteger call() throws Exception {
            return new EncryptedInteger(this.bi, this.pub_key);
        }

    }
    
    private final static class func_encryptInteger_1 implements Callable<BigInteger> {

        BigInteger bi_vec;
        PublicKey pub_key;

        public func_encryptInteger_1(BigInteger bi_vec, PublicKey pub_key) {
            this.bi_vec = bi_vec;
            this.pub_key = pub_key;
        }

        public func_encryptInteger_1(String bi_vec, PublicKey pub_key) {
            this.bi_vec = new BigInteger(bi_vec);
            this.pub_key = pub_key;
        }
        
        @Override
        public BigInteger call() throws Exception {
            return (new EncryptedInteger(this.bi_vec, this.pub_key)).getCipherVal();
        }
    }

    private final static class func_encryptVector implements Callable<EncryptedInteger[]> {

        BigInteger[] bi_vec;
        PublicKey pub_key;

        public func_encryptVector(BigInteger[] bi_vec, PublicKey pub_key) {
            this.bi_vec = bi_vec;
            this.pub_key = pub_key;
        }

        public func_encryptVector(String[] bi_vec, PublicKey pub_key) {
            this.bi_vec = new BigInteger[bi_vec.length];
            for (int n = 0; n < bi_vec.length; n++) {
                this.bi_vec[n] = new BigInteger(bi_vec[n]);
            }
            this.pub_key = pub_key;
        }
        
        public func_encryptVector(boolean[] bool_vec, PublicKey pub_key) {
            this.bi_vec = new BigInteger[bool_vec.length];
            
            for(int n = 0; n < bool_vec.length; n++){
                if(bool_vec[n]){
                    this.bi_vec[n] = BigInteger.ONE;
                }else{
                    this.bi_vec[n] = BigInteger.ZERO;
                }
            }
            
            this.pub_key = pub_key;
        }

        @Override
        public EncryptedInteger[] call() throws Exception {
            EncryptedInteger[] ret_vec = new EncryptedInteger[bi_vec.length];
            for (int n = 0; n < bi_vec.length; n++) {
                ret_vec[n] = new EncryptedInteger(bi_vec[n], pub_key);
            }
            return ret_vec;
        }
    }
    
    private final static class func_encryptVector_1 implements Callable<BigInteger[]> {

        BigInteger[] bi_vec;
        PublicKey pub_key;

        public func_encryptVector_1(BigInteger[] bi_vec, PublicKey pub_key) {
            this.bi_vec = bi_vec;
            this.pub_key = pub_key;
        }

        public func_encryptVector_1(String[] bi_vec, PublicKey pub_key) {
            this.bi_vec = new BigInteger[bi_vec.length];
            for (int n = 0; n < bi_vec.length; n++) {
                this.bi_vec[n] = new BigInteger(bi_vec[n]);
            }
            this.pub_key = pub_key;
        }
        
        public func_encryptVector_1(boolean[] bool_vec, PublicKey pub_key) {
            this.bi_vec = new BigInteger[bool_vec.length];
            
            for(int n = 0; n < bool_vec.length; n++){
                if(bool_vec[n]){
                    this.bi_vec[n] = BigInteger.ONE;
                }else{
                    this.bi_vec[n] = BigInteger.ZERO;
                }
            }
            
            this.pub_key = pub_key;
        }

        @Override
        public BigInteger[] call() throws Exception {
            BigInteger[] ret_vec = new BigInteger[bi_vec.length];
            for (int n = 0; n < bi_vec.length; n++) {
                ret_vec[n] = new EncryptedInteger(bi_vec[n], pub_key).getCipherVal();
            }
            return ret_vec;
        }
    }

    private final static class func_decryptEncInteger implements Callable<BigInteger> {

        EncryptedInteger enc_int;
        PrivateKey pri_key;

        public func_decryptEncInteger(EncryptedInteger enc_int, PrivateKey pri_key) {
            this.enc_int = enc_int;
            this.pri_key = pri_key;
        }

        @Override
        public BigInteger call() throws Exception {
            return enc_int.decrypt(pri_key);
        }

    }
    
    
    private final static class func_decryptEncInteger_1 implements Callable<BigInteger> {

        BigInteger enc_vec;
        BigInteger N;
        BigInteger NSquare;
        BigInteger Mu;
        BigInteger Lambda;

        public func_decryptEncInteger_1(BigInteger enc_vec, PrivateKey pri_key) {
            this.enc_vec = enc_vec;
            this.N = pri_key.getPublicKey().getN();
            this.NSquare = pri_key.getPublicKey().getNSquared();
            this.Mu = pri_key.getMu();
            this.Lambda = pri_key.getLambda();
        }

        @Override
        public BigInteger call() throws Exception {
            BigInteger plainval = enc_vec.modPow(Lambda, NSquare);
            plainval = plainval.subtract(BigInteger.ONE);
            plainval = plainval.divide(N);
            plainval = plainval.multiply(Mu);
            return plainval.mod(N);
        }
    }

    private final static class func_decryptEncVector implements Callable<BigInteger[]> {

        EncryptedInteger[] enc_vec;
        PrivateKey pri_key;

        public func_decryptEncVector(EncryptedInteger[] enc_vec, PrivateKey pri_key) {
            this.enc_vec = enc_vec;
            this.pri_key = pri_key;
        }

        @Override
        public BigInteger[] call() throws Exception {
            BigInteger[] ret_vec = new BigInteger[enc_vec.length];
            for (int n = 0; n < enc_vec.length; n++) {
                ret_vec[n] = enc_vec[n].decrypt(pri_key);
            }
            return ret_vec;
        }
    }
    
    private final static class func_decryptEncVector_1 implements Callable<BigInteger[]> {

        BigInteger[] enc_vec;
        BigInteger N;
        BigInteger NSquare;
        BigInteger Mu;
        BigInteger Lambda;

        public func_decryptEncVector_1(BigInteger[] enc_vec, PrivateKey pri_key) {
            this.enc_vec = enc_vec;
            this.N = pri_key.getPublicKey().getN();
            this.NSquare = pri_key.getPublicKey().getNSquared();
            this.Mu = pri_key.getMu();
            this.Lambda = pri_key.getLambda();
        }

        @Override
        public BigInteger[] call() throws Exception {
            BigInteger[] ret_vec = new BigInteger[enc_vec.length];
            for (int n = 0; n < enc_vec.length; n++) {
                BigInteger tmp_enc = enc_vec[n];
                
                BigInteger plainval = tmp_enc.modPow(Lambda, NSquare);
                plainval = plainval.subtract(BigInteger.ONE);
                plainval = plainval.divide(N);
		plainval = plainval.multiply(Mu);
		plainval = plainval.mod(N);              

                        
                ret_vec[n] = plainval;
            }
            return ret_vec;
        }
    }
    
    private final static class func_sumVec implements Callable<EncryptedInteger>{
        EncryptedInteger[] enc_vec;

        public func_sumVec(EncryptedInteger[] enc_vec) {
            this.enc_vec = enc_vec;
        }
        
        @Override
        public EncryptedInteger call() throws Exception {
            EncryptedInteger ret_enc_int = enc_vec[0];
            for(int n = 1;n < enc_vec.length; n++){
                ret_enc_int = ret_enc_int.add(enc_vec[n]);
            }
            return ret_enc_int;
        }
    }
    
    private final static class func_sumMat_col implements Callable<EncryptedInteger[]>{
        EncryptedInteger[][] enc_mat;

        public func_sumMat_col(EncryptedInteger[][] enc_mat) {
            this.enc_mat = enc_mat;
        }

        @Override
        public EncryptedInteger[] call() throws Exception {
            EncryptedInteger[] ret_enc_int = new EncryptedInteger[this.enc_mat[0].length];
            
            for (int n = 0; n < this.enc_mat[0].length; n++) {
                ret_enc_int[n] = enc_mat[0][n];
                for(int m = 1; m < enc_mat.length; m++){
                    ret_enc_int[n] = ret_enc_int[n].add(enc_mat[m][n]);
                }
            }
            return ret_enc_int;
        }
    }

    private final static class func_sumIntWithEncInt implements Callable<EncryptedInteger> {

        BigInteger int0;
        EncryptedInteger enc_int1;

        public func_sumIntWithEncInt(BigInteger int0, EncryptedInteger enc_int1) {
            this.int0 = int0;
            this.enc_int1 = enc_int1;
        }

        public func_sumIntWithEncInt(String str_int0, EncryptedInteger enc_int1) {
            this.int0 = new BigInteger(str_int0);
            this.enc_int1 = enc_int1;
        }

        @Override
        public EncryptedInteger call() throws Exception {
            return enc_int1.add(int0);
        }
    }
    
    private final static class func_sumIntWithEncInt_1 implements Callable<BigInteger> {

        BigInteger int0;
        BigInteger enc_int1;
        BigInteger g;
        BigInteger NSquared;

        public func_sumIntWithEncInt_1(BigInteger int0, BigInteger enc_int1, BigInteger g, BigInteger NSquared) {
            this.int0 = int0;
            this.enc_int1 = enc_int1;
            this.g = g;
            this.NSquared = NSquared;
        }

        public func_sumIntWithEncInt_1(String str_int0, BigInteger enc_int1, BigInteger g, BigInteger NSquared) {
            this.int0 = new BigInteger(str_int0);
            this.enc_int1 = enc_int1;
            this.g = g;
            this.NSquared = NSquared;
        }

        @Override
        public BigInteger call() throws Exception {
            return add(enc_int1, int0, g, NSquared);              
        }
    }

    private final static class func_sumVecWithEncVec implements Callable<EncryptedInteger[]> {

        BigInteger[] vec0;
        EncryptedInteger[] enc_vec1;

        public func_sumVecWithEncVec(BigInteger[] vec0, EncryptedInteger[] enc_vec1) {
            this.vec0 = vec0;
            this.enc_vec1 = enc_vec1;
        }

        public func_sumVecWithEncVec(String[] vec0, EncryptedInteger[] enc_vec1) {
            this.vec0 = new BigInteger[vec0.length];
            for (int n = 0; n < vec0.length; n++) {
                this.vec0[n] = new BigInteger(vec0[n]);
            }
            this.enc_vec1 = enc_vec1;
        }

        @Override
        public EncryptedInteger[] call() throws Exception {
            EncryptedInteger[] ret_enc_vec = new EncryptedInteger[enc_vec1.length];

            for (int n = 0; n < vec0.length; n++) {
                ret_enc_vec[n] = this.enc_vec1[n].add(vec0[n]);
            }
            return ret_enc_vec;
        }
    }

    private final static class func_sumTwoEncInts implements Callable<EncryptedInteger> {

        EncryptedInteger enc_int0;
        EncryptedInteger enc_int1;

        public func_sumTwoEncInts(EncryptedInteger enc_int0, EncryptedInteger enc_int1) {
            this.enc_int0 = enc_int0;
            this.enc_int1 = enc_int1;
        }

        @Override
        public EncryptedInteger call() throws Exception {
            return enc_int1.add(enc_int0);
        }
    }
    
    private final static class func_sumTwoEncInts_1 implements Callable<BigInteger> {

        BigInteger enc_int0;
        BigInteger enc_int1;
        BigInteger NSquared;

        public func_sumTwoEncInts_1(BigInteger enc_int0, BigInteger enc_int1, BigInteger NSquared) {
            this.enc_int0 = enc_int0;
            this.enc_int1 = enc_int1;
            this.NSquared = NSquared;
        }

        @Override
        public BigInteger call() throws Exception {
            return add1(enc_int0, enc_int1, NSquared);
        }
    }

    private final static class func_sumTwoEncVecs implements Callable<EncryptedInteger[]> {

        EncryptedInteger[] enc_vec0;
        EncryptedInteger[] enc_vec1;

        public func_sumTwoEncVecs(EncryptedInteger[] enc_vec0, EncryptedInteger[] enc_vec1) {
            this.enc_vec0 = enc_vec0;
            this.enc_vec1 = enc_vec1;
        }

        @Override
        public EncryptedInteger[] call() throws Exception {
            EncryptedInteger[] ret_enc_vec = new EncryptedInteger[enc_vec1.length];

            for (int n = 0; n < enc_vec0.length; n++) {
                ret_enc_vec[n] = this.enc_vec1[n].add(enc_vec0[n]);
            }
            return ret_enc_vec;
        }
    }
    
    private final static class func_subtractEncIntWithInt implements Callable<EncryptedInteger> {

        BigInteger int0;
        EncryptedInteger enc_int1;

        public func_subtractEncIntWithInt(EncryptedInteger enc_int1, BigInteger int0) {
            this.int0 = int0;
            this.enc_int1 = enc_int1;
        }

        public func_subtractEncIntWithInt(EncryptedInteger enc_int1, String str_int0) {
            this.int0 = new BigInteger(str_int0);
            this.enc_int1 = enc_int1;
        }

        @Override
        public EncryptedInteger call() throws Exception {
            return this.enc_int1.add(int0.negate().mod(this.enc_int1.getPublicKey().getN()));
        }
    }
    
    private final static class func_subtractEncVecWithVec implements Callable<EncryptedInteger[]> {

        BigInteger[] vec0;
        EncryptedInteger[] enc_vec1;

        public func_subtractEncVecWithVec(EncryptedInteger[] enc_vec1, BigInteger[] vec0) {
            this.vec0 = vec0;
            this.enc_vec1 = enc_vec1;
        }

        public func_subtractEncVecWithVec(EncryptedInteger[] enc_vec1, String[] vec0) {
            this.vec0 = new BigInteger[vec0.length];
            for (int n = 0; n < vec0.length; n++) {
                this.vec0[n] = new BigInteger(vec0[n]);
            }
            this.enc_vec1 = enc_vec1;
        }

        @Override
        public EncryptedInteger[] call() throws Exception {
            EncryptedInteger[] ret_enc_vec = new EncryptedInteger[enc_vec1.length];

            for (int n = 0; n < vec0.length; n++) {
                ret_enc_vec[n] = this.enc_vec1[n].add(vec0[n].negate().mod(this.enc_vec1[n].getPublicKey().getN()));
            }
            return ret_enc_vec;
        }
    }
    
    private final static class func_subtractEncVecWithInt implements Callable<EncryptedInteger[]> {

        BigInteger ne_int0;
        EncryptedInteger[] enc_vec1;

        public func_subtractEncVecWithInt(EncryptedInteger[] enc_vec1, BigInteger int0) {
            this.ne_int0 = int0.negate();
            this.enc_vec1 = enc_vec1;
        }

        public func_subtractEncVecWithInt(EncryptedInteger[] enc_vec1, String str_int0) {
            this.enc_vec1 = enc_vec1;
            this.ne_int0 = new BigInteger(str_int0).negate();
        }

        @Override
        public EncryptedInteger[] call() throws Exception {
            EncryptedInteger[] ret_enc_vec = new EncryptedInteger[enc_vec1.length];

            for (int n = 0; n < enc_vec1.length; n++) {
                ret_enc_vec[n] = this.enc_vec1[n].add(ne_int0);
            }
            return ret_enc_vec;
        }
    }
    
    private final static class func_subtractEncVecWithInt_1 implements Callable<BigInteger[]> {

        BigInteger ne_int0;
        BigInteger[] enc_vec1;
        BigInteger g;
        BigInteger NSquared;

        public func_subtractEncVecWithInt_1(BigInteger[] enc_vec1, BigInteger int0, BigInteger g, BigInteger NSquared) {
            this.ne_int0 = int0.negate();
            this.enc_vec1 = enc_vec1;
            this.g = g;
            this.NSquared = NSquared;
        }

        public func_subtractEncVecWithInt_1(BigInteger[] enc_vec1, String str_int0 , BigInteger g, BigInteger NSquared) {
            this.enc_vec1 = enc_vec1;
            this.ne_int0 = new BigInteger(str_int0).negate();
            this.g = g;
            this.NSquared = NSquared;
        }

        @Override
        public BigInteger[] call() throws Exception {
            BigInteger[] ret_enc_vec = new BigInteger[enc_vec1.length];

            for (int n = 0; n < enc_vec1.length; n++) {
                ret_enc_vec[n] = add(enc_vec1[n], ne_int0, g, NSquared);
            }
            return ret_enc_vec;
        }
    }

    private final static class func_mulIntWithEncInt implements Callable<EncryptedInteger> {

        BigInteger int0;
        EncryptedInteger enc_int1;

        public func_mulIntWithEncInt(BigInteger int0, EncryptedInteger enc_int1) {
            this.int0 = int0;
            this.enc_int1 = enc_int1;
        }

        public func_mulIntWithEncInt(String str_int0, EncryptedInteger enc_int1) {
            this.int0 = new BigInteger(str_int0);
            this.enc_int1 = enc_int1;
        }

        @Override
        public EncryptedInteger call() throws Exception {
            return this.enc_int1.multiply(int0);
        }
    }

    private final static class func_mulVecWithEncVecPairwise implements Callable<EncryptedInteger[]> {

        BigInteger[] vec0;
        EncryptedInteger[] enc_vec1;

        public func_mulVecWithEncVecPairwise(BigInteger[] vec0, EncryptedInteger[] enc_vec1) {
            this.vec0 = vec0;
            this.enc_vec1 = enc_vec1;
        }

        public func_mulVecWithEncVecPairwise(String[] str_vec0, EncryptedInteger[] enc_vec1) {
            this.vec0 = new BigInteger[str_vec0.length];

            for (int n = 0; n < str_vec0.length; n++) {
                this.vec0[n] = new BigInteger(str_vec0[n]);
            }

            this.enc_vec1 = enc_vec1;
        }

        @Override
        public EncryptedInteger[] call() throws Exception {
            EncryptedInteger[] ret_enc_vec = new EncryptedInteger[enc_vec1.length];

            for (int n = 0; n < vec0.length; n++) {
                ret_enc_vec[n] = this.enc_vec1[n].multiply(vec0[n]);
            }
            return ret_enc_vec;
        }
    }
    
    private final static class func_mulVecWithEncVecPairwise_1 implements Callable<BigInteger[]> {

        BigInteger[] vec0;
        EncryptedInteger[] enc_vec1;

        public func_mulVecWithEncVecPairwise_1(BigInteger[] vec0, EncryptedInteger[] enc_vec1) {
            this.vec0 = vec0;
            this.enc_vec1 = enc_vec1;
        }

        public func_mulVecWithEncVecPairwise_1(String[] str_vec0, EncryptedInteger[] enc_vec1) {
            this.vec0 = new BigInteger[str_vec0.length];

            for (int n = 0; n < str_vec0.length; n++) {
                this.vec0[n] = new BigInteger(str_vec0[n]);
            }

            this.enc_vec1 = enc_vec1;
        }

        @Override
        public BigInteger[] call() throws Exception {
            BigInteger[] ret_enc_vec = new BigInteger[enc_vec1.length];

            for (int n = 0; n < vec0.length; n++) {
                ret_enc_vec[n] = this.enc_vec1[n].multiply(vec0[n]).getCipherVal();
            }
            return ret_enc_vec;
        }
    }
    
    private final static class func_mulVecWithEncVecPairwise_2 implements Callable<BigInteger[]> {

        BigInteger[] vec0;
        BigInteger[] enc_vec1;
        BigInteger NSquared;

        public func_mulVecWithEncVecPairwise_2(BigInteger[] vec0, BigInteger[] enc_vec1, BigInteger NSquared) {
            this.vec0 = vec0;
            this.enc_vec1 = enc_vec1;
            this.NSquared = NSquared;
        }

        public func_mulVecWithEncVecPairwise_2(String[] str_vec0, BigInteger[] enc_vec1, BigInteger NSquared) {
            this.vec0 = new BigInteger[str_vec0.length];

            for (int n = 0; n < str_vec0.length; n++) {
                this.vec0[n] = new BigInteger(str_vec0[n]);
            }

            this.enc_vec1 = enc_vec1;
            this.NSquared = NSquared;
        }

        @Override
        public BigInteger[] call() throws Exception {
            BigInteger[] ret_enc_vec = new BigInteger[enc_vec1.length];

            for (int n = 0; n < vec0.length; n++) {
                ret_enc_vec[n] = mul(enc_vec1[n], vec0[n], NSquared);
            }
            return ret_enc_vec;
        }
    }

    private final static class func_mulVecWithEncMat implements Callable<EncryptedInteger[]> {

        BigInteger[] vec;
        EncryptedInteger[][] enc_mat;

        public func_mulVecWithEncMat(BigInteger[] vec, EncryptedInteger[][] enc_mat) {
            this.vec = vec;
            this.enc_mat = enc_mat;
        }
        
        public func_mulVecWithEncMat(String[] str_vec, EncryptedInteger[][] enc_mat) {
            this.vec = new BigInteger[str_vec.length];
            for(int n = 0; n < str_vec.length; n++){
                this.vec[n] = new BigInteger(str_vec[n]);
            }
            this.enc_mat = enc_mat;
        }

        @Override
        public EncryptedInteger[] call() throws Exception {
            EncryptedInteger[] ret_enc_vec = new EncryptedInteger[enc_mat[0].length];

            for (int n = 0; n < ret_enc_vec.length; n++) {
                ret_enc_vec[n] = enc_mat[0][n].multiply(vec[0]);
                for (int m = 1; m < vec.length; m++) {
                    ret_enc_vec[n] = ret_enc_vec[n].add(enc_mat[m][n].multiply(vec[m]));
                }
            }

            return ret_enc_vec;
        }
    }
    
    private static BigInteger add(BigInteger enc_data0, BigInteger data1, BigInteger g, BigInteger NSquared) {
        return enc_data0.multiply(g.modPow(data1, NSquared)).mod(NSquared);
    }
    
    private static BigInteger add1(BigInteger enc_data0, BigInteger enc_data1, BigInteger NSquared){		
		return enc_data0.multiply(enc_data1).mod(NSquared);
    }
    
    private static BigInteger mul(BigInteger enc_data0, BigInteger data1, BigInteger NSquared){
        return enc_data0.modPow(data1, NSquared);
    }

    public static EncryptedInteger[] encrypt(BigInteger[] vector, PublicKey public_key) throws InterruptedException, ExecutionException {
        EncryptedInteger[] ret_enc = new EncryptedInteger[vector.length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<EncryptedInteger>[] enc_integer = new Future[vector.length];

        for (int m = 0; m < vector.length; m++) {
            enc_integer[m] = pool.submit(new func_encryptInteger(vector[m], public_key));
        }

        for (int m = 0; m < vector.length; m++) {
            ret_enc[m] = enc_integer[m].get();
        }

        pool.shutdown();

        return ret_enc;
    }

    public static EncryptedInteger[] encrypt(String[] vector, PublicKey public_key) throws InterruptedException, ExecutionException {
        EncryptedInteger[] ret_enc = new EncryptedInteger[vector.length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<EncryptedInteger>[] enc_integer = new Future[vector.length];

        for (int m = 0; m < vector.length; m++) {
            enc_integer[m] = pool.submit(new func_encryptInteger(vector[m], public_key));
        }

        for (int m = 0; m < vector.length; m++) {
            ret_enc[m] = enc_integer[m].get();
        }

        pool.shutdown();

        return ret_enc;
    }

    //need juint
    public static BigInteger[] encrypt1(BigInteger[] vector, PublicKey public_key) throws InterruptedException, ExecutionException {
        BigInteger[] ret_enc = new BigInteger[vector.length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<BigInteger>[] enc_vec = new Future[vector.length];

        for (int m = 0; m < vector.length; m++) {
            enc_vec[m] = pool.submit(new func_encryptInteger_1(vector[m], public_key));
        }

        for (int m = 0; m < vector.length; m++) {
            ret_enc[m] = enc_vec[m].get();
        }

        pool.shutdown();

        return ret_enc;
    }

    public static EncryptedInteger[][] encrypt(BigInteger[][] matrix, PublicKey public_key) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc = new EncryptedInteger[matrix.length][matrix[0].length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<EncryptedInteger[]>[] enc_vec = new Future[matrix.length];

        for (int m = 0; m < matrix.length; m++) {
            enc_vec[m] = pool.submit(new func_encryptVector(matrix[m], public_key));
        }

        for (int m = 0; m < matrix.length; m++) {
            ret_enc[m] = enc_vec[m].get();
        }

        pool.shutdown();

        return ret_enc;
    }

    public static EncryptedInteger[][] encrypt(String[][] matrix, PublicKey public_key) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc = new EncryptedInteger[matrix.length][matrix[0].length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<EncryptedInteger[]>[] enc_vec = new Future[matrix.length];

        for (int m = 0; m < matrix.length; m++) {
            enc_vec[m] = pool.submit(new func_encryptVector(matrix[m], public_key));
        }

        for (int m = 0; m < matrix.length; m++) {
            ret_enc[m] = enc_vec[m].get();
        }

        pool.shutdown();

        return ret_enc;
    }
    
    //need junit
    public static BigInteger[][] encrypt1(BigInteger[][] matrix, PublicKey public_key) throws InterruptedException, ExecutionException {
        BigInteger[][] ret_enc = new BigInteger[matrix.length][matrix[0].length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<BigInteger[]>[] enc_vec = new Future[matrix.length];

        for (int m = 0; m < matrix.length; m++) {
            enc_vec[m] = pool.submit(new func_encryptVector_1(matrix[m], public_key));
        }

        for (int m = 0; m < matrix.length; m++) {
            ret_enc[m] = enc_vec[m].get();
        }

        pool.shutdown();

        return ret_enc;
    }
    //need junit
    public static EncryptedInteger[][][] encrypt(boolean[][][] bi_matrix, PublicKey public_key) throws InterruptedException, ExecutionException {
        EncryptedInteger[][][] ret_enc = new EncryptedInteger[bi_matrix.length][bi_matrix[0].length][];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<EncryptedInteger[]>[][] enc_vec = new Future[bi_matrix.length][bi_matrix[0].length];

        for (int m = 0; m < bi_matrix.length; m++) {
            for(int n = 0; n < bi_matrix[m].length; n++){
                enc_vec[m][n] = pool.submit(new func_encryptVector(bi_matrix[m][n], public_key));
            }
        }

        for (int m = 0; m < bi_matrix.length; m++) {
            for(int n = 0; n < bi_matrix[m].length; n++){
                ret_enc[m][n] = enc_vec[m][n].get();
            }
        }

        pool.shutdown();

        return ret_enc;
    }

    public static BigInteger[] decrypt(EncryptedInteger[] enc_vector, PrivateKey prv_key) throws InterruptedException, ExecutionException {
        BigInteger[] ret_vec = new BigInteger[enc_vector.length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<BigInteger>[] future_integer = new Future[enc_vector.length];

        for (int m = 0; m < enc_vector.length; m++) {
            future_integer[m] = pool.submit(new func_decryptEncInteger(enc_vector[m], prv_key));
        }

        for (int m = 0; m < enc_vector.length; m++) {
            ret_vec[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_vec;
    }
    
    public static BigInteger[] decrypt(BigInteger[] enc_vec, PrivateKey prv_key) throws InterruptedException, ExecutionException {
        BigInteger[] ret_vec = new BigInteger[enc_vec.length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<BigInteger>[] future_integer = new Future[enc_vec.length];

        for (int m = 0; m < enc_vec.length; m++) {
            future_integer[m] = pool.submit(new func_decryptEncInteger_1(enc_vec[m], prv_key));
        }

        for (int m = 0; m < enc_vec.length; m++) {
            ret_vec[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_vec;
    }

    public static BigInteger[][] decrypt(EncryptedInteger[][] enc_mat, PrivateKey prv_key) throws InterruptedException, ExecutionException {
        BigInteger[][] ret_mat = new BigInteger[enc_mat.length][enc_mat[0].length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<BigInteger[]>[] future_integer = new Future[enc_mat.length];

        for (int m = 0; m < enc_mat.length; m++) {
            future_integer[m] = pool.submit(new func_decryptEncVector(enc_mat[m], prv_key));
        }

        for (int m = 0; m < enc_mat.length; m++) {
            ret_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_mat;
    }
    
    //need junit
    public static BigInteger[][] decrypt(BigInteger[][] enc_mat, PrivateKey prv_key) throws InterruptedException, ExecutionException {
        BigInteger[][] ret_mat = new BigInteger[enc_mat.length][enc_mat[0].length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<BigInteger[]>[] future_integer = new Future[enc_mat.length];

        for (int m = 0; m < enc_mat.length; m++) {
            future_integer[m] = pool.submit(new func_decryptEncVector_1(enc_mat[m], prv_key));
        }

        for (int m = 0; m < enc_mat.length; m++) {
            ret_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_mat;
    }
    
    //need juint
    public static BigInteger[] sum(BigInteger[] enc_vec0, BigInteger int1, BigInteger g, BigInteger NSquared) throws InterruptedException, ExecutionException {
        BigInteger[] ret_enc_vec = new BigInteger[enc_vec0.length];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<BigInteger>[] future_integer = new Future[enc_vec0.length];
        
        for (int m = 0; m < enc_vec0.length; m++) {
            future_integer[m] = pool.submit(new func_sumIntWithEncInt_1(int1, enc_vec0[m], g, NSquared));
        }

        for (int m = 0; m < enc_vec0.length; m++) {
            ret_enc_vec[m] = future_integer[m].get();
        }
        
        return ret_enc_vec;
    }
    
    public static EncryptedInteger[] sum(EncryptedInteger[][] enc_mat0) throws InterruptedException, ExecutionException {
        EncryptedInteger[] ret_enc_vec = new EncryptedInteger[enc_mat0.length];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger>[] future_integer = new Future[enc_mat0.length];

        for (int m = 0; m < enc_mat0.length; m++) {
            future_integer[m] = pool.submit(new func_sumVec(enc_mat0[m]));
        }

        for (int m = 0; m < enc_mat0.length; m++) {
            ret_enc_vec[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_vec;
    }
    
    public static EncryptedInteger[][] sum3DIn1DDirection(EncryptedInteger[][][] enc_mat0) throws InterruptedException, ExecutionException{
        EncryptedInteger[][] ret_enc_mat = new EncryptedInteger[enc_mat0[0].length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        
        Future<EncryptedInteger[]>[] future_integer = new Future[enc_mat0[0].length];
        
        for (int m = 0; m < enc_mat0[0].length; m++) {
            EncryptedInteger[][] tmp = new EncryptedInteger[enc_mat0.length][];
            for(int k = 0; k < enc_mat0.length; k++){
                tmp[k] = enc_mat0[k][m];
            }
            future_integer[m] = pool.submit(new func_sumMat_col(tmp));  
        }
        
        for (int m = 0; m < enc_mat0[0].length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }
        
        pool.shutdown();
        
        return ret_enc_mat;
    }

    //need juint
    public static BigInteger[] sum(BigInteger[] enc_vec0, BigInteger[] enc_vec1, BigInteger NSquared) throws InterruptedException, ExecutionException {
        BigInteger[] ret_enc_vec = new BigInteger[enc_vec0.length];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<BigInteger>[] future_integer = new Future[enc_vec0.length];

        for (int m = 0; m < enc_vec1.length; m++) {
            future_integer[m] = pool.submit(new func_sumTwoEncInts_1(enc_vec0[m], enc_vec1[m], NSquared));
        }

        for (int m = 0; m < enc_vec1.length; m++) {
            ret_enc_vec[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_vec;
    }
    
    public static EncryptedInteger[] sum(BigInteger[] vec0, EncryptedInteger[] enc_vec1) throws InterruptedException, ExecutionException {
        EncryptedInteger[] ret_enc_vec = new EncryptedInteger[vec0.length];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger>[] future_integer = new Future[vec0.length];

        for (int m = 0; m < enc_vec1.length; m++) {
            future_integer[m] = pool.submit(new func_sumIntWithEncInt(vec0[m], enc_vec1[m]));
        }

        for (int m = 0; m < enc_vec1.length; m++) {
            ret_enc_vec[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_vec;
    }

    public static EncryptedInteger[] sum(String[] vec0, EncryptedInteger[] enc_vec1) throws InterruptedException, ExecutionException {
        EncryptedInteger[] ret_enc_vec = new EncryptedInteger[vec0.length];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger>[] future_integer = new Future[vec0.length];

        for (int m = 0; m < enc_vec1.length; m++) {
            future_integer[m] = pool.submit(new func_sumIntWithEncInt(vec0[m], enc_vec1[m]));
        }

        for (int m = 0; m < enc_vec1.length; m++) {
            ret_enc_vec[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_vec;
    }

    public static EncryptedInteger[][] sum(BigInteger[][] mat0, EncryptedInteger[][] enc_mat1) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc_mat = new EncryptedInteger[mat0.length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger[]>[] future_integer = new Future[mat0.length];

        for (int m = 0; m < enc_mat1.length; m++) {
            future_integer[m] = pool.submit(new func_sumVecWithEncVec(mat0[m], enc_mat1[m]));
        }

        for (int m = 0; m < enc_mat1.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }

    public static EncryptedInteger[][] sum(String[][] mat0, EncryptedInteger[][] enc_mat1) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc_mat = new EncryptedInteger[mat0.length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger[]>[] future_integer = new Future[mat0.length];

        for (int m = 0; m < enc_mat1.length; m++) {
            future_integer[m] = pool.submit(new func_sumVecWithEncVec(mat0[m], enc_mat1[m]));
        }

        for (int m = 0; m < enc_mat1.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }

    public static EncryptedInteger[] sum(EncryptedInteger[] enc_vec0, EncryptedInteger[] enc_vec1) throws InterruptedException, ExecutionException {
        EncryptedInteger[] ret_enc_vec = new EncryptedInteger[enc_vec0.length];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger>[] future_integer = new Future[enc_vec0.length];

        for (int m = 0; m < enc_vec1.length; m++) {
            future_integer[m] = pool.submit(new func_sumTwoEncInts(enc_vec0[m], enc_vec1[m]));
        }

        for (int m = 0; m < enc_vec1.length; m++) {
            ret_enc_vec[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_vec;
    }

    public static EncryptedInteger[][] sum(EncryptedInteger[][] enc_mat0, EncryptedInteger[][] enc_mat1) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc_mat = new EncryptedInteger[enc_mat0.length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger[]>[] future_integer = new Future[enc_mat0.length];

        for (int m = 0; m < enc_mat1.length; m++) {
            future_integer[m] = pool.submit(new func_sumTwoEncVecs(enc_mat0[m], enc_mat1[m]));
        }

        for (int m = 0; m < enc_mat1.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }
    
    //need juint
    public static EncryptedInteger[] subtract(EncryptedInteger[] enc_vec1, BigInteger[] vec0) throws InterruptedException, ExecutionException {
        EncryptedInteger[] ret_enc_vec = new EncryptedInteger[vec0.length];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger>[] future_integer = new Future[vec0.length];

        for (int m = 0; m < enc_vec1.length; m++) {
            future_integer[m] = pool.submit(new func_subtractEncIntWithInt(enc_vec1[m], vec0[m]));
        }

        for (int m = 0; m < enc_vec1.length; m++) {
            ret_enc_vec[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_vec;
    }
       
    //need juint
    public static EncryptedInteger[][] subtract(EncryptedInteger[][] enc_mat1, BigInteger[][] mat0) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc_mat = new EncryptedInteger[mat0.length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger[]>[] future_integer = new Future[mat0.length];

        for (int m = 0; m < enc_mat1.length; m++) {
            future_integer[m] = pool.submit(new func_subtractEncVecWithVec(enc_mat1[m], mat0[m]));
        }

        for (int m = 0; m < enc_mat1.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }
    
    public static EncryptedInteger[][] subtract_out(EncryptedInteger[] enc_vec1, BigInteger[] vec0) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc_mat = new EncryptedInteger[vec0.length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger[]>[] future_integer = new Future[vec0.length];

        for (int m = 0; m < vec0.length; m++) {
            future_integer[m] = pool.submit(new func_subtractEncVecWithInt(enc_vec1, vec0[m]));
        }

        for (int m = 0; m < vec0.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }

    //need junit
    public static BigInteger[][] subtract_out(BigInteger[] enc_vec1, BigInteger[] vec0, BigInteger g, BigInteger NSquared) throws InterruptedException, ExecutionException {
        BigInteger[][] ret_enc_mat = new BigInteger[vec0.length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<BigInteger[]>[] future_integer = new Future[vec0.length];

        for (int m = 0; m < vec0.length; m++) {
            future_integer[m] = pool.submit(new func_subtractEncVecWithInt_1(enc_vec1, vec0[m], g, NSquared));
        }

        for (int m = 0; m < vec0.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }

    public static EncryptedInteger[] mul(BigInteger[] vec0, EncryptedInteger[] enc_vec1) throws InterruptedException, ExecutionException {
        EncryptedInteger[] ret_enc_vec = new EncryptedInteger[vec0.length];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger>[] future_integer = new Future[vec0.length];

        for (int m = 0; m < enc_vec1.length; m++) {
            future_integer[m] = pool.submit(new func_mulIntWithEncInt(vec0[m], enc_vec1[m]));
        }

        for (int m = 0; m < enc_vec1.length; m++) {
            ret_enc_vec[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_vec;
    }

    public static EncryptedInteger[] mul(String[] vec0, EncryptedInteger[] enc_vec1) throws InterruptedException, ExecutionException {
        EncryptedInteger[] ret_enc_vec = new EncryptedInteger[vec0.length];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger>[] future_integer = new Future[vec0.length];

        for (int m = 0; m < enc_vec1.length; m++) {
            future_integer[m] = pool.submit(new func_mulIntWithEncInt(vec0[m], enc_vec1[m]));
        }

        for (int m = 0; m < enc_vec1.length; m++) {
            ret_enc_vec[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_vec;
    }

    public static EncryptedInteger[][] mul(BigInteger[][] mat0, EncryptedInteger[][] enc_mat1) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc_mat = new EncryptedInteger[mat0.length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger[]>[] future_integer = new Future[mat0.length];

        for (int m = 0; m < enc_mat1.length; m++) {
            future_integer[m] = pool.submit(new func_mulVecWithEncVecPairwise(mat0[m], enc_mat1[m]));
        }

        for (int m = 0; m < enc_mat1.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }
    
    // require junit
    public static BigInteger[][] mul1(BigInteger[][] mat0, EncryptedInteger[][] enc_mat1) throws InterruptedException, ExecutionException {
        BigInteger[][] ret_enc_mat = new BigInteger[mat0.length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<BigInteger[]>[] future_integer = new Future[mat0.length];

        for (int m = 0; m < enc_mat1.length; m++) {
            future_integer[m] = pool.submit(new func_mulVecWithEncVecPairwise_1(mat0[m], enc_mat1[m]));
        }

        for (int m = 0; m < enc_mat1.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }
    
    // require junit
    public static BigInteger[][] mul1(BigInteger[][] mat0, BigInteger[][] enc_mat1, BigInteger NSquared) throws InterruptedException, ExecutionException {
        BigInteger[][] ret_enc_mat = new BigInteger[mat0.length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<BigInteger[]>[] future_integer = new Future[mat0.length];

        for (int m = 0; m < enc_mat1.length; m++) {
            future_integer[m] = pool.submit(new func_mulVecWithEncVecPairwise_2(mat0[m], enc_mat1[m], NSquared));
        }

        for (int m = 0; m < enc_mat1.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }

    public static EncryptedInteger[][] mul(String[][] mat0, EncryptedInteger[][] enc_mat1) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc_mat = new EncryptedInteger[mat0.length][];
        ExecutorService pool = Executors.newFixedThreadPool(thread_num);
        Future<EncryptedInteger[]>[] future_integer = new Future[mat0.length];

        for (int m = 0; m < enc_mat1.length; m++) {
            future_integer[m] = pool.submit(new func_mulVecWithEncVecPairwise(mat0[m], enc_mat1[m]));
        }

        for (int m = 0; m < enc_mat1.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }

    public static EncryptedInteger[][] mulMatwithEncMat(BigInteger[][] mat0, EncryptedInteger[][] enc_mat1) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc_mat = new EncryptedInteger[mat0.length][enc_mat1[0].length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<EncryptedInteger[]>[] future_integer = new Future[mat0.length];

        for (int m = 0; m < mat0.length; m++) {
            future_integer[m] = pool.submit(new func_mulVecWithEncMat(mat0[m], enc_mat1));
        }

        for (int m = 0; m < mat0.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }
    
    public static EncryptedInteger[][] mulMatwithEncMat(String[][] mat0, EncryptedInteger[][] enc_mat1) throws InterruptedException, ExecutionException {
        EncryptedInteger[][] ret_enc_mat = new EncryptedInteger[mat0.length][enc_mat1[0].length];

        ExecutorService pool = Executors.newFixedThreadPool(thread_num);

        Future<EncryptedInteger[]>[] future_integer = new Future[mat0.length];

        for (int m = 0; m < mat0.length; m++) {
            future_integer[m] = pool.submit(new func_mulVecWithEncMat(mat0[m], enc_mat1));
        }

        for (int m = 0; m < mat0.length; m++) {
            ret_enc_mat[m] = future_integer[m].get();
        }

        pool.shutdown();

        return ret_enc_mat;
    }
}
