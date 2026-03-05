import * as tls from "node:tls";

export type TlsDeep = {
  negotiatedVersion?: string;
  cipher?: string;
  weakCipher: boolean;
  selfSigned: boolean;
  issuer?: string;
};

// Cipher names that indicate weak/broken encryption
const WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5", "RC2"];

export async function getTlsDeep(domain: string): Promise<TlsDeep> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ weakCipher: false, selfSigned: false });
    }, 12_000);

    let done = false;
    const finish = (result: TlsDeep) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { socket.destroy(); } catch { /* ignore */ }
      resolve(result);
    };

    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const negotiatedVersion = socket.getProtocol() ?? undefined;
          const cipherObj = socket.getCipher();
          const cipherName = cipherObj?.name ?? "";

          const issuerO = cert?.issuer?.O ?? undefined;
          // Self-signed: issuer CN == subject CN and issuer O == subject O
          const selfSigned =
            !!cert?.issuer?.CN &&
            cert.issuer.CN === cert.subject?.CN &&
            cert.issuer.O === cert.subject?.O;

          const weakCipher = WEAK_CIPHER_KEYWORDS.some((w) =>
            cipherName.toUpperCase().includes(w)
          );

          finish({
            negotiatedVersion,
            cipher: cipherName || undefined,
            weakCipher,
            selfSigned,
            issuer: typeof issuerO === "string" ? issuerO : undefined,
          });
        } catch {
          finish({ weakCipher: false, selfSigned: false });
        }
      }
    );

    socket.on("error", () => finish({ weakCipher: false, selfSigned: false }));
  });
}
