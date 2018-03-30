/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.apim.custom;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class JWTSignatureValidator {

    private String signAlgorithm;
    private Certificate certificate;

    private static final Log log = LogFactory.getLog(JWTSignatureValidator.class);

    public void setSignAlgorithm(String signAlgorithm) {
        this.signAlgorithm = signAlgorithm;
    }
    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public JWTSignatureValidator(String signAlgorithm, Certificate certificate) {
        this.signAlgorithm = signAlgorithm;
        this.certificate = certificate;
    }

    /**
     * Validates jwt signature against the certificate.
     *
     * @param assersion
     * @param signature
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public boolean validateSignature(String assersion, String signature) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException,
            InvalidKeyException, SignatureException {
        if (signAlgorithm.equals("RS256")) {
            signAlgorithm = "SHA256withRSA";
        }
        PublicKey publicKey = certificate.getPublicKey();
        Signature signatureInstance = Signature.getInstance(signAlgorithm);
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(assersion.getBytes());
        byte[] decodedBytes = Base64Utils.decode(signature);
        return signatureInstance.verify(decodedBytes);
    }
}
