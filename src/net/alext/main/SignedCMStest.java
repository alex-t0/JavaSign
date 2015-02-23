package net.alext.main;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;

public class SignedCMStest {

    public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, OperatorCreationException, CMSException {
        // char[] password = "111111".toCharArray();
        char[] password = "1".toCharArray();
        String text = "text";

        // FileInputStream fis = new FileInputStream("/data/3/soft/devel/GitHub/BeginningCryptographyJava/certstore.jks");
        FileInputStream fis = new FileInputStream("/data/3/soft/devel/GitHub/BeginningCryptographyJava/Sert3.pfx");
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(fis, password);

        String alias = ks.aliases().nextElement();
        PrivateKey pKey = (PrivateKey)ks.getKey(alias, password);
        X509Certificate cert = (X509Certificate)ks.getCertificate(alias);
        java.util.List certList = new ArrayList();
        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").setDirectSignature(true);

        gen.addSignerInfoGenerator(builder.build("SHA1withRSA", pKey, cert));
        gen.addCertificates(certs);

        byte[] textBytes = text.getBytes("utf-8");
        CMSTypedData msg = new CMSProcessableByteArray(textBytes);
        CMSSignedData s = gen.generate(msg, true);
        byte[] encoded = s.getEncoded();
        String b64 = Base64.getEncoder().encodeToString(encoded);
        System.out.println(b64);
    }
}
