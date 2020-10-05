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
import com.itextpdf.text.pdf.security.CertificateVerifier;
import com.itextpdf.text.pdf.security.LtvVerification.CertificateOption;
import com.itextpdf.text.pdf.security.LtvVerifier;
import com.itextpdf.text.pdf.security.OCSPVerifier;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.VerificationException;
import com.itextpdf.text.pdf.security.VerificationOK;
import id.go.bppt.ptik.pdfverification.test.TestVerify;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.crypto.interfaces.DHPublicKey;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author Rachmawan
 */
public class Verifier {

    KeyStore ks;
    private Logger logger;

    public static final String IOTENTIK_CA_G1 = "D:\\iOTENTIK\\2020\\Certs_iOTENTIK\\iOTENTIK CA G1.cer";
    public static final String IOTENTIK_ROOT_CA = "D:\\iOTENTIK\\2020\\Certs_iOTENTIK\\Root CA iOTENTIK.cer";

    public PdfPKCS7 verifySignature(AcroFields fields, String name) throws GeneralSecurityException, IOException, UnrecognizedSignatureException {
        logger.info(String.format("%-40s%s\n", "Signature covers whole document", fields.signatureCoversWholeDocument(name)));
        logger.info(String.format("%-40s%s\n", "Document Revision", fields.getRevision(name) + " of " + fields.getTotalRevisions()));

        PdfPKCS7 pkcs7 = fields.verifySignature(name);
        logger.info(String.format(name, "%-40s%s\n", "Integrity check OK?", pkcs7.verify()));

        Certificate[] myChain = pkcs7.getSignCertificateChain();
        Date signDate = pkcs7.getSignDate().getTime();
        
        verifyChain(myChain, signDate);

        if (pkcs7.isTsp()) {
            logger.info(StringUtils.center("BEGIN TSP READING", 60, '='));

            TimeStampToken token = pkcs7.getTimeStampToken();
            TimeStampTokenInfo tsInfo = token.getTimeStampInfo();

            Store store = token.getCertificates();

            Collection<X509CertificateHolder> holders = store.getMatches(token.getSID());

            for (X509CertificateHolder certHolder : holders) {
                X509Certificate certFromTSA = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certHolder);

                logger.info(String.format("%-40s%s\n", "Issuer", certFromTSA.getIssuerDN().toString()));
                logger.info(String.format("%-40s%s\n", "Subject", certFromTSA.getSubjectDN().toString()));
            }

            logger.info(tsInfo.getSerialNumber().toString(16));
            logger.info(tsInfo.getGenTime().toString());

            logger.info(String.format("%-40s%s\n", "TSA Serial Number", tsInfo.getSerialNumber().toString(16)));
            logger.info(String.format("%-40s%s\n", "TSA Generation Time", tsInfo.getGenTime()));

            logger.info(StringUtils.center("END TSP READING", 60, '='));

            return pkcs7;
        }

        logger.info(String.format("%-40s%s\n", "SignName", pkcs7.getSignName()));
        Certificate[] certs = pkcs7.getCertificates();
        Calendar cal = pkcs7.getSignDate();
        List<VerificationException> errors = CertificateVerification.verifyCertificates(certs, ks, cal);

        if (errors.isEmpty()) {
            logger.info(StringUtils.center("Certificate(s) verified against the Keystore", 60, '='));
        } else {
            logger.error(StringUtils.center("ERROR(S)!!", 60, '='));
            for (int i = 0; i < errors.size(); i++) {
                logger.error(String.format("%3s %s\n", (i + 1), errors.get(i).getMessage()));
            }

//            throw new UnrecognizedSignatureException("Unrecognized Certificate(s)!");
        }

        Certificate[] awal = new Certificate[1];
        awal[0] = certs[1];
        List<VerificationException> errors2 = CertificateVerification.verifyCertificates(awal, ks, cal);
        if (errors2.isEmpty()) {
            logger.info(StringUtils.center("Certificate(s) verified against the Keystore", 60, '='));
        } else {
            logger.error(StringUtils.center("ERROR(S)!!", 60, '='));
            logger.error(String.format("%3s %s\n", "1", errors2));
        }

        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = (X509Certificate) certs[i];
            logger.info(StringUtils.center("Certificate " + i, 60, '='));
            showCertificateInfo(cert, cal.getTime());
        }
        X509Certificate signCert = (X509Certificate) certs[0];
        X509Certificate issuerCert = (certs.length > 1 ? (X509Certificate) certs[1] : null);

//        logger.info(StringUtils.center("Checking validity of the document at the time of signing", 60, '='));
//        checkRevocation(pkcs7, signCert, issuerCert, cal.getTime());
//
//        logger.info(StringUtils.center("Checking validity of the document today", 60, '='));
//        checkRevocation(pkcs7, signCert, issuerCert, new Date());

        return pkcs7;
    }

    public void verifyChain(Certificate[] chain, Date signDate) throws GeneralSecurityException {
        // Loop over the certificates in the chain
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = (X509Certificate) chain[i];
            // check if the certificate was/is valid
            cert.checkValidity(signDate);
            // check if the previous certificate was issued by this certificate
            if (i > 0) {
                chain[i - 1].verify(chain[i].getPublicKey());
            }
        }
        logger.info("All certificates are valid on " + signDate.toString());
    }

    public void validate(PdfReader reader)
            throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ks.setCertificateEntry("ca_g1",
                cf.generateCertificate(new FileInputStream(IOTENTIK_CA_G1)));
        ks.setCertificateEntry("root_ca",
                cf.generateCertificate(new FileInputStream(IOTENTIK_ROOT_CA)));
        CertificateVerifier custom = new CertificateVerifier(null) {
            public List<VerificationOK> verify(
                    X509Certificate signCert, X509Certificate issuerCert, Date signDate)
                    throws GeneralSecurityException, IOException {
                System.out.println(signCert.getSubjectDN().getName()
                        + ": ALL VERIFICATIONS DONE");
                return new ArrayList<VerificationOK>();
            }
        };
        LtvVerifier data = new LtvVerifier(reader);
        data.setRootStore(ks);
        data.setCertificateOption(CertificateOption.WHOLE_CHAIN);
        data.setVerifier(custom);
        data.setOnlineCheckingAllowed(true);
        data.setVerifyRootCertificate(false);
        List<VerificationOK> list = new ArrayList<VerificationOK>();
        try {
            data.verify(list);
        } catch (GeneralSecurityException e) {
            System.err.println(e.getMessage());
        }
        System.out.println();
        if (list.size() == 0) {
            System.out.println("The document can't be verified");
        }
        for (VerificationOK v : list) {
            System.out.println(v.toString());
        }
    }

    public void checkRevocation(PdfPKCS7 pkcs7, X509Certificate signCert, X509Certificate issuerCert, Date date) throws GeneralSecurityException, IOException {
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
            logger.error(StringUtils.center("The signing certificate couldn't be verified", 60, '='));
        } else {
            verification.forEach((v) -> {
                logger.info(v.toString());
            });
        }
    }

    public void showCertificateInfo(X509Certificate cert, Date signDate) throws CertificateExpiredException, CertificateNotYetValidException {

        logger.info(String.format("%-40s%s\n", "Issuer", cert.getIssuerDN().getName()));
        logger.info(String.format("%-40s%s\n", "Subject", cert.getSubjectDN().getName()));
        logger.info(String.format("%-40s%s\n", "Serial Number", cert.getSerialNumber().toString(16)));

        int len;

        if (cert.getPublicKey() instanceof RSAPublicKey) {
            RSAPublicKey rsaPk = (RSAPublicKey) cert.getPublicKey();
            len = rsaPk.getModulus().bitLength();
            logger.info(String.format("%-40s%s\n", "Public Key Type", "RSA Public Key (" + len + " bit)"));
        } else if (cert.getPublicKey() instanceof DSAPublicKey) {
            DSAPublicKey dsaPk = (DSAPublicKey) cert.getPublicKey();
            len = dsaPk.getY().bitLength();
            logger.info(String.format("%-40s%s\n", "Public Key Type", "DSA Public Key (" + len + " bit)"));
        } else if (cert.getPublicKey() instanceof ECPublicKey) {
            logger.info(String.format("%-40s%s\n", "Public Key Type", "EC Public Key"));
        } else if (cert.getPublicKey() instanceof DHPublicKey) {
            DHPublicKey dhPk = (DHPublicKey) cert.getPublicKey();
            len = dhPk.getY().bitLength();
            logger.info(String.format("%-40s%s\n", "Public Key Type", "DH Public Key (" + len + " bit)"));
        } else {
            logger.info(String.format("%-40s%s\n", "Public Key Type", "Unknown Public Key Type"));
        }

        logger.info(String.format("%-40s%s\n", "Signature Algorithm", cert.getSigAlgName()));

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA1");
            byte[] result = digest.digest(cert.getEncoded());
            String hex = Hex.toHexString(result).toUpperCase();
            String res = StringFormatter.insertPeriodically(hex, "::", 2);
            logger.info(String.format("%-40s%s\n", "SHA1 Fingerprint", res));
        } catch (NoSuchAlgorithmException | CertificateEncodingException ex) {
            logger.error(ex.getMessage());
        }

        SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
        logger.info(String.format("%-40s%s\n", "Valid from", date_format.format(cert.getNotBefore())));
        logger.info(String.format("%-40s%s\n", "Valid to", date_format.format(cert.getNotAfter())));

        try {
            cert.checkValidity(signDate);
            logger.info(StringUtils.center("The certificate was valid at the time of signing.", 60, '='));
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            logger.error(StringUtils.center(e.getMessage(), 60, '='));
        }

        try {
            cert.checkValidity();
            logger.info(StringUtils.center("The certificate is still valid.", 60, '='));
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            logger.error(StringUtils.center(e.getMessage(), 60, '='));
        }
    }

    public void verifySignatures(String path) throws IOException, GeneralSecurityException, UnrecognizedSignatureException {
//        logger.info(path);
        PdfReader reader = new PdfReader(path);
//        PdfReader reader = new PdfReader(new URL("https://blogs.adobe.com/security/SampleSignedPDFDocument.pdf").openStream());
//        PdfReader reader = new PdfReader(new URL("https://teken.govca.id/storage/signpdf/demo/15.04.1062_cover_signed_15489103175c527eed768b46.pdf").openStream());
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();

        for (String name : names) {
//            logger.info("===== " + name + " =====");
            logger.info(StringUtils.center(name, 60, '='));

            logger.info(String.format("%-40s%s\n", "Signature covers whole document", fields.signatureCoversWholeDocument(name)));
            logger.info(String.format("%-40s%s\n", "Document Revision", fields.getRevision(name) + " of " + fields.getTotalRevisions()));
            PdfPKCS7 pkcs7 = fields.verifySignature(name);
            logger.info(String.format("%-40s%s\n", "Integrity check OK?", pkcs7.verify()));
            verifySignature(fields, name);

            if (fields.signatureCoversWholeDocument(name))
                validate(reader);
        }
    }

    private void setKeyStore(KeyStore ks) {
        this.ks = ks;
    }

    public Verifier(KeyStore ks_param, Logger logger) {
        setKeyStore(ks_param);
        setLogger(logger);
    }

    /**
     * @return the logger
     */
    public Logger getLogger() {
        return logger;
    }

    /**
     * @param logger the logger to set
     */
    public void setLogger(Logger logger) {
        this.logger = logger;
    }
}
