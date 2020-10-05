/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pdfverification.test;

import id.go.bppt.ptik.pdfverification.utils.UnrecognizedSignatureException;
import id.go.bppt.ptik.pdfverification.utils.Verifier;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampTokenInfo;

/**
 *
 * @author Rachmawan
 */
public class TestVerify {

    public static final String BPPT = "D:\\Tugas PTIK\\Pemilu Elektronik\\BANTAENG - JUNI 2018\\Certificate Chain\\Badan_Pengkajian_dan_Penerapan_Teknologi.cer";
    public static final String IOTENTIK = "D:\\Tugas PTIK\\Pemilu Elektronik\\BANTAENG - JUNI 2018\\Certificate Chain\\iOTENTIK_Badan_Pengkajian_dan_Penerapan_Teknologi_.cer";
    public static final String KPU = "D:\\Tugas PTIK\\Pemilu Elektronik\\BANTAENG - JUNI 2018\\Certificate Chain\\KPU_KOMISI_PEMILIHAN_UMUM_iOTENTIK_.cer";
    public static final String RACHMAWAN = "D:\\Tugas PTIK\\Pemilu Elektronik\\BANTAENG - JUNI 2018\\Certificate Chain\\Rachmawan_Atmaji_KPU_KOMISI_PEMILIHAN_UMUM_.cer";
    
    public static final String DEV = "D:\\Tugas PTIK\\Certificate Authority\\iOTENTIK 2019\\iOTENTIK_Dev.cer";
    public static final String ROOT = "D:\\Tugas PTIK\\Certificate Authority\\iOTENTIK 2019\\iOTENTIK_Root.cer";

    public static final String ROOT_SERVER = "/home/ipteknet/kpu/pdf_certs/BPPT_Root.cer";
    public static final String IOTENTIK_SERVER = "/home/ipteknet/kpu/pdf_certs/iOTENTIK.cer";
    public static final String KPU_SERVER = "/home/ipteknet/kpu/pdf_certs/KPU.cer";
    
    public static final String ROOT_LOCAL = "D:\\E-PEMILU\\pdf_certs\\BPPT_Root.cer";
    public static final String IOTENTIK_LOCAL = "D:\\E-PEMILU\\pdf_certs\\iOTENTIK.cer";
    public static final String KPU_LOCAL = "D:\\E-PEMILU\\pdf_certs\\KPU.cer";
    
    public static final String IOTENTIK_ROOT_CA = "D:\\iOTENTIK\\2020\\Certs_iOTENTIK\\Root CA iOTENTIK.cer";
    public static final String IOTENTIK_CA_G1 = "D:\\iOTENTIK\\2020\\Certs_iOTENTIK\\iOTENTIK CA G1.cer";
    
    public static final String DOC_SERVER = "/home/ipteknet/kpu/java_pdf_01/cf0031f1-36f8-420e-bd8b-52552ef8f501.pdf";
//    public static final String DOC = "D:\\E-PEMILU\\7423027e-89c4-40a2-a24c-246488f910be.pdf";
//    public static final String DOC = "D:\\iOTENTIK\\2019\\SISUMAKER NG\\202001212227141693.pdf";
    public static final String DOC = "D:\\iOTENTIK\\2020\\Test Doc-G1-TSA.pdf";
//    public static final String DOC = "D:\\iOTENTIK\\2020\\BoardingPass_signedByDarius.pdf";
    
    private static final Logger log = LogManager.getLogger(TestVerify.class);
    
    
    
    public static void main(String[] args) {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        //This is the root logger provided by log4j
        Logger rootLogger = LogManager.getRootLogger();
        log.debug("test");
        rootLogger.info("tesku");

        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");            
            
            ks.setCertificateEntry("ca_g1",
                    cf.generateCertificate(new FileInputStream(IOTENTIK_CA_G1)));
            ks.setCertificateEntry("iotentik_root",
                    cf.generateCertificate(new FileInputStream(IOTENTIK_ROOT_CA)));
            
//            ks.setCertificateEntry("root",
//                    cf.generateCertificate(new FileInputStream(ROOT_LOCAL)));
//            ks.setCertificateEntry("iotentik",
//                    cf.generateCertificate(new FileInputStream(IOTENTIK_LOCAL)));
//            ks.setCertificateEntry("kpu",
//                    cf.generateCertificate(new FileInputStream(KPU_LOCAL)));
//            ks.setCertificateEntry("rachmawan",
//                    cf.generateCertificate(new FileInputStream(RACHMAWAN)));
            
            Verifier verify = new Verifier(ks, (org.apache.logging.log4j.Logger) log);
            verify.verifySignatures(DOC);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
//            Logger.getLogger(TestVerify.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (GeneralSecurityException | UnrecognizedSignatureException ex) {
//            Logger.getLogger(TestVerify.class.getName()).log(Level.SEVERE, null, ex);
        } catch (GeneralSecurityException | UnrecognizedSignatureException ex) {
            java.util.logging.Logger.getLogger(TestVerify.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }

    }
}
