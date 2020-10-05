/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pdfverification.utils;

import com.itextpdf.text.log.Level;
import com.itextpdf.text.log.Logger;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.pdf.security.CRLVerifier;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CertificateVerifier;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.RootStoreVerifier;
import com.itextpdf.text.pdf.security.VerificationException;
import com.itextpdf.text.pdf.security.VerificationOK;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/**
 *
 * @author waone
 */
public class MyOCSPVerifier extends RootStoreVerifier {

    /**
     * The Logger instance
     */
    protected final static Logger LOGGER = LoggerFactory.getLogger(MyOCSPVerifier.class);

    protected final static String id_kp_OCSPSigning = "1.3.6.1.5.5.7.3.9";

    /**
     * The list of OCSP responses.
     */
    protected List<BasicOCSPResp> ocsps;

    public MyOCSPVerifier(CertificateVerifier verifier, List<BasicOCSPResp> ocsps) {
        super(verifier);
        this.ocsps = ocsps;
    }

    public List<VerificationOK> verify(X509Certificate signCert,
            X509Certificate issuerCert, Date signDate)
            throws GeneralSecurityException, IOException {
        List<VerificationOK> result = new ArrayList<VerificationOK>();
        int validOCSPsFound = 0;
        // first check in the list of OCSP responses that was provided
        if (ocsps != null) {
            for (BasicOCSPResp ocspResp : ocsps) {
                if (verify(ocspResp, signCert, issuerCert, signDate)) {
                    validOCSPsFound++;
                }
            }
        }
        // then check online if allowed
        boolean online = false;
        if (onlineCheckingAllowed && validOCSPsFound == 0) {
            if (verify(getOcspResponse(signCert, issuerCert), signCert, issuerCert, signDate)) {
                validOCSPsFound++;
                online = true;
            }
        }
        // show how many valid OCSP responses were found
        LOGGER.info("Valid OCSPs found: " + validOCSPsFound);
        if (validOCSPsFound > 0) {
            result.add(new VerificationOK(signCert, this.getClass(), "Valid OCSPs Found: " + validOCSPsFound + (online ? " (online)" : "")));
        }
        if (verifier != null) {
            result.addAll(verifier.verify(signCert, issuerCert, signDate));
        }
        // verify using the previous verifier in the chain (if any)
        return result;
    }

    /**
     * Verifies a certificate against a single OCSP response
     *
     * @param ocspResp the OCSP response
     * @param signCert the certificate that needs to be checked
     * @param issuerCert the certificate of CA
     * @param signDate sign date
     * @return {@code true}, in case successful check, otherwise false.
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public boolean verify(BasicOCSPResp ocspResp, X509Certificate signCert, X509Certificate issuerCert, Date signDate) throws GeneralSecurityException, IOException {
        if (ocspResp == null) {
            return false;
        }
        // Getting the responses
        SingleResp[] resp = ocspResp.getResponses();
        for (int i = 0; i < resp.length; i++) {
            // check if the serial number corresponds
            if (!signCert.getSerialNumber().equals(resp[i].getCertID().getSerialNumber())) {
                continue;
            }
            // check if the issuer matches
            try {
                if (issuerCert == null) {
                    issuerCert = signCert;
                }
                if (!resp[i].getCertID().matchesIssuer(new X509CertificateHolder(issuerCert.getEncoded()), new BcDigestCalculatorProvider())) {
                    LOGGER.info("OCSP: Issuers doesn't match.");
                    continue;
                }
            } catch (OCSPException e) {
                continue;
            }
            // check if the OCSP response was valid at the time of signing
            Date nextUpdate = resp[i].getNextUpdate();
            if (nextUpdate == null) {
                nextUpdate = new Date(resp[i].getThisUpdate().getTime() + 180000l);
                if (LOGGER.isLogging(Level.INFO)) {
                    LOGGER.info(String.format("No 'next update' for OCSP Response; assuming %s", nextUpdate));
                }
            }
            if (signDate.after(nextUpdate)) {
                if (LOGGER.isLogging(Level.INFO)) {
                    LOGGER.info(String.format("OCSP no longer valid: %s after %s", signDate, nextUpdate));
                }
                continue;
            }
            // check the status of the certificate
            Object status = resp[i].getCertStatus();
            if (status == CertificateStatus.GOOD) {
                // check if the OCSP response was genuine
                isValidResponse(ocspResp, issuerCert);
                return true;
            }
        }
        return false;
    }

    /**
	 * Verifies if an OCSP response is genuine
	 * @param ocspResp	the OCSP response
	 * @param issuerCert	the issuer certificate
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public void isValidResponse(BasicOCSPResp ocspResp, X509Certificate issuerCert) throws GeneralSecurityException, IOException {
		// by default the OCSP responder certificate is the issuer certificate
		X509Certificate responderCert = issuerCert;
		// check if there's a responder certificate
		X509CertificateHolder[] certHolders = ocspResp.getCerts();
		if (certHolders.length > 0) {
			responderCert = new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate(certHolders[0]);
			try {
				responderCert.verify(issuerCert.getPublicKey());
			}
			catch(GeneralSecurityException e) {
				if (super.verify(responderCert, issuerCert, null).size() == 0)
					throw new VerificationException(responderCert, "Responder certificate couldn't be verified");
			}
		}
		// verify if the signature of the response is valid
		if (!verifyResponse(ocspResp, responderCert))
			throw new VerificationException(responderCert, "OCSP response could not be verified");
	}

    /**
     * Verifies if the response is valid. If it doesn't verify against the
     * issuer certificate and response's certificates, it may verify using a
     * trusted anchor or cert. NOTE. Use {@code isValidResponse()} instead.
     *
     * @param ocspResp	the response object
     * @param issuerCert the issuer certificate
     * @return	true if the response can be trusted
     */
    @Deprecated
    public boolean verifyResponse(BasicOCSPResp ocspResp, X509Certificate issuerCert) {
        try {
            isValidResponse(ocspResp, issuerCert);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Checks if an OCSP response is genuine
     *
     * @param ocspResp	the OCSP response
     * @param responderCert	the responder certificate
     * @return	true if the OCSP response verifies against the responder
     * certificate
     */
    public boolean isSignatureValid(BasicOCSPResp ocspResp, Certificate responderCert) {
        try {
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC").build(responderCert.getPublicKey());
            return ocspResp.isSignatureValid(verifierProvider);
        } catch (OperatorCreationException e) {
            return false;
        } catch (OCSPException e) {
            return false;
        }
    }

    /**
     * Gets an OCSP response online and returns it if the status is GOOD
     * (without further checking).
     *
     * @param signCert	the signing certificate
     * @param issuerCert	the issuer certificate
     * @return an OCSP response
     */
    public BasicOCSPResp getOcspResponse(X509Certificate signCert, X509Certificate issuerCert) {
        if (signCert == null && issuerCert == null) {
            return null;
        }
        OcspClientBouncyCastle ocsp = new OcspClientBouncyCastle();
        BasicOCSPResp ocspResp = ocsp.getBasicOCSPResp(signCert, issuerCert, null);
        if (ocspResp == null) {
            return null;
        }
        SingleResp[] resp = ocspResp.getResponses();
        for (int i = 0; i < resp.length; i++) {
            Object status = resp[i].getCertStatus();
            if (status == CertificateStatus.GOOD) {
                return ocspResp;
            }
        }
        return null;
    }

}
