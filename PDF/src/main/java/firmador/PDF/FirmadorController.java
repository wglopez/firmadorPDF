package firmador.PDF;



import lombok.RequiredArgsConstructor;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PdfPKCS7;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;


@Controller
@RequiredArgsConstructor
@RequestMapping("/firmadorPdf")
public class FirmadorController {
	
	static byte[] toSign;
    static byte[] hash;
	private static final String PRIVATE_KEY_PATH = "/home/walter/Descargas/Eclipse/PDF/private_key.pem";
    private static final String CERTIFICATE_PATH = "/home/walter/Descargas/Eclipse/PDF/cert.pem";
    private static final String FIELDNAME="sign";
	
	@PostMapping()
    public ResponseEntity<String> firmarPdf(@RequestBody String base64) {
		
		try {
            // Obtener documento PDF
            byte[] documento = obtenerDocumento(base64);

            // Preparar documento PDF
            byte[] documentoPreparado = prepararDocumento(documento);

            // Generar PKCS7
            byte[] pkcs7 = generarPKCS7(hash);

            // Insertar firma digital en el documento PDF
            byte[] documentoFirmado = firmarDocumento(documentoPreparado, pkcs7);

            // Devolver el documento firmado
            return ResponseEntity.ok(Base64.getEncoder().encodeToString(documentoFirmado));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Error al firmar el documento");
        }
		
	}
	
	
	private byte[] obtenerDocumento(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    private byte[] prepararDocumento(byte[] documento) throws Exception {
        PdfReader reader = new PdfReader(documento);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setVisibleSignature(new Rectangle(0,0,0,0), 1, FIELDNAME);
        appearance.setReason("Firma remota de SIGNAR");
        appearance.setLocation("Santa Fe");

        ExternalSignatureContainer external = new EmptyContainer();
        MakeSignature.signExternalContainer(appearance, external, 8192);
        
        stamper.close();
        reader.close();
        return baos.toByteArray();
    }


    private byte[] generarPKCS7(byte[] hash) throws Exception {
        // Cargar clave privada y certificado
        PrivateKey privateKey = obtenerClavePrivada();
        Certificate[] certificado = obtenerCertificado();

        // Crear PKCS7
        PdfPKCS7 sgn = new PdfPKCS7(privateKey, certificado, "SHA-256", null, null, false);
        toSign = sgn.getAuthenticatedAttributeBytes(hash, null, null, MakeSignature.CryptoStandard.CMS);
        
        sgn.update(toSign, 0, toSign.length);
        return sgn.getEncodedPKCS7(hash);
    }

    //se debe cargar el documento preparado
    private byte[] firmarDocumento(byte[] documento, byte[] pkcs7) throws Exception {
        PdfReader reader = new PdfReader(documento);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();        
        
        ExternalSignatureContainer external = new MyExternalSignatureContainer(pkcs7);
        MakeSignature.signDeferred(reader, FIELDNAME, baos, external);
        
        
        reader.close();
        return baos.toByteArray();
    }

    private PrivateKey obtenerClavePrivada() throws Exception {
    	PemReader pemReader = new PemReader(new FileReader(PRIVATE_KEY_PATH));
        PemObject pemObject = pemReader.readPemObject();
        byte[] keyBytes = pemObject.getContent();
        pemReader.close();

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private Certificate[] obtenerCertificado() throws Exception {
    	CertificateFactory fact = CertificateFactory.getInstance("X.509");
        InputStream is = new FileInputStream(CERTIFICATE_PATH);
        X509Certificate cert = (X509Certificate) fact.generateCertificate(is);
        return new Certificate[]{cert};
    }
    
    
    private static class EmptyContainer implements ExternalSignatureContainer {
        @Override
        public byte[] sign(InputStream data) throws GeneralSecurityException {
            try {
                // Create an ExternalDigest instance
                ExternalDigest digest = new ExternalDigest() {
                    @Override
                    public MessageDigest getMessageDigest(String algorithm) throws NoSuchAlgorithmException {
                        return MessageDigest.getInstance(algorithm);
                    }
                };

                // Calculate the hash of the document
                hash = DigestAlgorithms.digest(data, digest.getMessageDigest("SHA-256"));

                // Create PdfPKCS7 instance
                Certificate[] certChain = {null};
                PdfPKCS7 pkcs7 = new PdfPKCS7(null, certChain, "SHA-256", null, digest, false);

                // Get authenticated attribute bytes
                toSign = pkcs7.getAuthenticatedAttributeBytes(hash, null, null, MakeSignature.CryptoStandard.CMS);

                // Sign the authenticated attributes
                // Implement signing logic here
                return new byte[0]; // You need to return the actual signed bytes here
            } catch (IOException | GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }

		@Override
		public void modifySigningDictionary(PdfDictionary pdfDictionary) {
            pdfDictionary.put(PdfName.FILTER, PdfName.ADOBE_PPKMS);
            pdfDictionary.put(PdfName.SUBFILTER, PdfName.ADBE_PKCS7_DETACHED);
        }
    }

    private static class MyExternalSignatureContainer implements ExternalSignatureContainer {
        private final byte[] signature;

        public MyExternalSignatureContainer(byte[] signature) {
            this.signature = signature;
        }

        @Override
        public byte[] sign(InputStream is) {
            return signature;
        }

        @Override
        public void modifySigningDictionary(PdfDictionary pdfDictionary) {
            // No modifications needed
        }
    }

}
