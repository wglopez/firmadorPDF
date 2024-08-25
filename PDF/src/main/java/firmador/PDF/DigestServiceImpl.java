package firmador.PDF;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.springframework.stereotype.Service;

@Service
public class DigestServiceImpl{
	public byte[] obtenerDigest(byte[] documento) throws NoSuchAlgorithmException, NoSuchProviderException{
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "BC");
		return sha256.digest(documento);
    }
	
	
	public byte[] obtenerDigest(InputStream documento) throws NoSuchAlgorithmException, NoSuchProviderException, IOException{
		MessageDigest digest;
		digest = MessageDigest.getInstance("SHA-256", "BC");
    	byte[] buffer = new byte[4096];
        int bytesRead;
		while ((bytesRead = documento.read(buffer)) != -1) {
		    digest.update(buffer, 0, bytesRead);
		}
        return digest.digest();
        
    }
	
}