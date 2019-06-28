/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pdfverification.test;

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
import java.util.logging.Level;
import java.util.logging.Logger;
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

//    public static final String DOC = "D:\\Tugas PTIK\\Pemilu Elektronik\\WebSocketC1Server\\35f0509f-50ec-4b77-afb3-8114af3b19b4.pdf";
    public static final String DOC = "D:\\Tugas PTIK\\Certificate Authority\\iOTENTIK 2019\\tes_TSA.pdf";
    
    public static void main(String[] args) {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
//            ks.setCertificateEntry("root",
//                    cf.generateCertificate(new FileInputStream(ROOT)));
            ks.setCertificateEntry("dev",
                    cf.generateCertificate(new FileInputStream(DEV)));
//            ks.setCertificateEntry("kpu",
//                    cf.generateCertificate(new FileInputStream(KPU)));
//            ks.setCertificateEntry("rachmawan",
//                    cf.generateCertificate(new FileInputStream(RACHMAWAN)));
            
            Verifier verify = new Verifier(ks);
            verify.verifySignatures(DOC);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(TestVerify.class.getName()).log(Level.SEVERE, null, ex);
        } catch (GeneralSecurityException ex) {
            Logger.getLogger(TestVerify.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
