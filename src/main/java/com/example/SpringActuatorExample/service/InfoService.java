package com.example.SpringActuatorExample.service;

import lombok.SneakyThrows;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

@Component
public class InfoService implements InfoContributor {

    @SneakyThrows
    @Override
    public void contribute(Info.Builder builder) {

        HashMap<String, LocalDate> certsexpirationtime = new HashMap<>();
        List<X509Certificate> xcerts = new ArrayList<>();
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(new KeyManager[0], new TrustManager[]{new NotSecureTrustManager()}, new SecureRandom());
        SSLContext.setDefault(ctx);
        URL url = new URL("https://localhost");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setHostnameVerifier((String arg0, SSLSession arg1) -> true);
        conn.connect();
        Certificate[] certs = conn.getServerCertificates();
        for (Certificate cert : certs) {
            Long l = ((X509Certificate) cert).getNotAfter().getTime();

            LocalDate date = Instant.ofEpochMilli(l)
                    .atZone(ZoneId.systemDefault())
                    .toLocalDate();

            builder.withDetail(((X509Certificate) cert).getSigAlgName(), date);
        }
        conn.disconnect();
    }

    private static class NotSecureTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
}

