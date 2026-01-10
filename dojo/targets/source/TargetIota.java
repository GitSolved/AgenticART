package com.example.iota;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

public class PinnedTrustManager implements X509TrustManager {
    // VULNERABILITY: Custom TrustManager logic.
    // Agent must hook checkServerTrusted to bypass exception.
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("Pinning Verification Failed!");
    }
}
