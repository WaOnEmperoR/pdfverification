/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pdfverification.utils;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CRLVerifier;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.OCSPVerifier;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.VerificationException;
import com.itextpdf.text.pdf.security.VerificationOK;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.interfaces.DHPublicKey;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Rachmawan
 */
public class Verifier {

    KeyStore ks;

    public PdfPKCS7 verifySignature(AcroFields fields, String name) throws GeneralSecurityException, IOException {
        System.out.println("Signature covers whole document: " + fields.signatureCoversWholeDocument(name));
        System.out.println("Document revision: " + fields.getRevision(name) + " of " + fields.getTotalRevisions());
        PdfPKCS7 pkcs7 = fields.verifySignature(name);
        System.out.println("Integrity check OK? " + pkcs7.verify());

        if (pkcs7.isTsp()) {
            System.out.println("---THIS IS TSP---");
            System.out.println("===Begin TSP Reading===");
            TimeStampToken token = pkcs7.getTimeStampToken();
            TimeStampTokenInfo tsInfo = token.getTimeStampInfo();

            Store store = token.getCertificates();
            
            Collection<X509CertificateHolder> holders = store.getMatches(token.getSID());
            
            for (X509CertificateHolder certHolder : holders) {
                X509Certificate certFromTSA = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certHolder);
                
                System.out.println("Issuer: " + certFromTSA.getIssuerDN());
                System.out.println("Subject: " + certFromTSA.getSubjectDN());
            }

            System.out.println(tsInfo.getSerialNumber().toString(16));
            System.out.println(tsInfo.getGenTime().toString());
            
            System.out.println("===End TSP Reading===");
            
            return pkcs7;
        }

        Certificate[] certs = pkcs7.getCertificates();
        Calendar cal = pkcs7.getSignDate();
        List<VerificationException> errors = CertificateVerification.verifyCertificates(certs, ks, cal);
        if (errors.isEmpty()) {
            System.out.println("Certificates verified against the KeyStore");
        } else {
            System.out.println(errors);
        }
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = (X509Certificate) certs[i];
            System.out.println("=== Certificate " + i + " ===");
            showCertificateInfo(cert, cal.getTime());
        }
        X509Certificate signCert = (X509Certificate) certs[0];
        X509Certificate issuerCert = (certs.length > 1 ? (X509Certificate) certs[1] : null);
        System.out.println("=== Checking validity of the document at the time of signing ===");
        checkRevocation(pkcs7, signCert, issuerCert, cal.getTime());
        System.out.println("=== Checking validity of the document today ===");
        checkRevocation(pkcs7, signCert, issuerCert, new Date());
        return pkcs7;
    }

    public static void checkRevocation(PdfPKCS7 pkcs7, X509Certificate signCert, X509Certificate issuerCert, Date date) throws GeneralSecurityException, IOException {
        List<BasicOCSPResp> ocsps = new ArrayList<>();
        if (pkcs7.getOcsp() != null) {
            ocsps.add(pkcs7.getOcsp());
        }
        OCSPVerifier ocspVerifier = new OCSPVerifier(null, ocsps);
        List<VerificationOK> verification
                = ocspVerifier.verify(signCert, issuerCert, date);
        if (verification.isEmpty()) {
            List<X509CRL> crls = new ArrayList<>();
            if (pkcs7.getCRLs() != null) {
                pkcs7.getCRLs().forEach((crl) -> {
                    crls.add((X509CRL) crl);
                });
            }
            CRLVerifier crlVerifier = new CRLVerifier(null, crls);
            verification.addAll(crlVerifier.verify(signCert, issuerCert, date));
        }
        if (verification.isEmpty()) {
            System.out.println("The signing certificate couldn't be verified");
        } else {
            verification.forEach((v) -> {
                System.out.println(v);
            });
        }
    }

    public void showCertificateInfo(X509Certificate cert, Date signDate) throws CertificateExpiredException, CertificateNotYetValidException {
        System.out.println("Issuer: " + cert.getIssuerDN());
        System.out.println("Subject: " + cert.getSubjectDN());
        System.out.println("Serial Number: " + cert.getSerialNumber().toString(16));
        
        int len;
        
        System.out.print("Public Key Type: ");
        if (cert.getPublicKey() instanceof RSAPublicKey)
        {
            RSAPublicKey rsaPk = (RSAPublicKey) cert.getPublicKey();
            len = rsaPk.getModulus().bitLength();
            System.out.println("RSA Public Key (" + len + " bit)");
        }
        else if(cert.getPublicKey() instanceof DSAPublicKey)
        {
            DSAPublicKey dsaPk = (DSAPublicKey) cert.getPublicKey();
            len = dsaPk.getY().bitLength();
            System.out.println("DSA Public Key (" + len + " bit)");
        }
        else if(cert.getPublicKey() instanceof ECPublicKey)
        {
            System.out.println("EC Public Key");
        }
        else if(cert.getPublicKey() instanceof DHPublicKey)
        {
            DHPublicKey dhPk = (DHPublicKey) cert.getPublicKey();
            len = dhPk.getY().bitLength();
            System.out.println("DH Public Key (" + len + " bit)");
        }
        else
        {
            System.out.println("Unknown Public Key Type");
        }
        
        System.out.println("Signature Algorithm: " + cert.getSigAlgName());
        
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA1");
            byte[] result = digest.digest(cert.getEncoded());
            String hex = Hex.toHexString(result).toUpperCase();
            String res = StringFormatter.insertPeriodically(hex, "::", 2);
            System.out.println("SHA1 Fingerprint: " + res);
        } catch (NoSuchAlgorithmException | CertificateEncodingException ex) {
            Logger.getLogger(Verifier.class.getName()).log(Level.SEVERE, null, ex);
        }

        SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
        System.out.println("Valid from: " + date_format.format(cert.getNotBefore()));
        System.out.println("Valid to: " + date_format.format(cert.getNotAfter()));
        
        try {
            cert.checkValidity(signDate);
            System.out.println("The certificate was valid at the time of signing.");
        } catch (CertificateExpiredException e) {
            System.out.println("The certificate was valid expired at the time of signing.");
        } catch (CertificateNotYetValidException e) {
            System.out.println("The certificate was not valid at the time of signing..");
        }
        
        try {
            cert.checkValidity();
            System.out.println("The certificate is still valid.");
        } catch (CertificateExpiredException e) {
            System.out.println("The certificate has expired.");
        } catch (CertificateNotYetValidException e) {
            System.out.println("The certificate isn't valid yet.");
        }
    }

    public void verifySignatures(String path) throws IOException, GeneralSecurityException {
        System.out.println(path);
        PdfReader reader = new PdfReader(path);
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();

        for (String name : names) {
            System.out.println("===== " + name + " =====");
            verifySignature(fields, name);
        }
        System.out.println();
    }

    private void setKeyStore(KeyStore ks) {
        this.ks = ks;
    }

    public Verifier(KeyStore ks_param) {
        setKeyStore(ks_param);
    }
}
