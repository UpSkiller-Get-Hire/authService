package org.UPSkiller.Util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.core.io.Resource;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class RsaKeyLoader {
    @Value("classpath:Keys/private.pem")
    private Resource privateKeyResource;

    @Value("classpath:Keys/public.pem")
    private Resource publicKeyResource;

    public PrivateKey loadPrivateKey() throws Exception{
        String key = new String(privateKeyResource.getInputStream().readAllBytes());
        key = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s","");

        byte [] decoded = Base64.getDecoder().decode(key);

        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    public PublicKey loadPublicKey() throws Exception{
        String key = new String(publicKeyResource.getInputStream().readAllBytes());
        key = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s","");
        byte [] decoded = Base64.getDecoder().decode(key);

        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
    }
}
