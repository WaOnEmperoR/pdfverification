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

/**
 *
 * @author Rachmawan
 */
public class TestVerify {

    public static final String BPPT = "D:\\Tugas PTIK\\Pemilu Elektronik\\BANTAENG - JUNI 2018\\Certificate Chain\\Badan_Pengkajian_dan_Penerapan_Teknologi.cer";
    public static final String IOTENTIK = "D:\\Tugas PTIK\\Pemilu Elektronik\\BANTAENG - JUNI 2018\\Certificate Chain\\iOTENTIK_Badan_Pengkajian_dan_Penerapan_Teknologi_.cer";
    public static final String KPU = "D:\\Tugas PTIK\\Pemilu Elektronik\\BANTAENG - JUNI 2018\\Certificate Chain\\KPU_KOMISI_PEMILIHAN_UMUM_iOTENTIK_.cer";
    public static final String RACHMAWAN = "D:\\Tugas PTIK\\Pemilu Elektronik\\BANTAENG - JUNI 2018\\Certificate Chain\\Rachmawan_Atmaji_KPU_KOMISI_PEMILIHAN_UMUM_.cer";

    public static final String DOC = "D:\\Tugas PTIK\\Pemilu Elektronik\\f27aac65-48ed-444d-bc3d-1f8d7d2dd217.pdf_SIGNED.pdf";
    
    public static void main(String[] args) {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ks.setCertificateEntry("bppt",
                    cf.generateCertificate(new FileInputStream(BPPT)));
            ks.setCertificateEntry("iotentik",
                    cf.generateCertificate(new FileInputStream(IOTENTIK)));
            ks.setCertificateEntry("kpu",
                    cf.generateCertificate(new FileInputStream(KPU)));
            ks.setCertificateEntry("rachmawan",
                    cf.generateCertificate(new FileInputStream(RACHMAWAN)));
            
            Verifier verify = new Verifier(ks);
            verify.verifySignatures(DOC);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(TestVerify.class.getName()).log(Level.SEVERE, null, ex);
        } catch (GeneralSecurityException ex) {
            Logger.getLogger(TestVerify.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
