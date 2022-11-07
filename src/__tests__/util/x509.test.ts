import { toDER } from '../../util/pem';
import { parseCertificate } from '../../util/x509';

describe('parseX509Certificate', () => {
  const pem = `-----BEGIN CERTIFICATE-----
MIICnjCCAiWgAwIBAgIUZMcoh64XV4XCcSQYwJrXU22UjlUwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjIxMDI0MTk1MDQ3WhcNMjIxMDI0MjAwMDQ3WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEtP3jL42xsHewiWX1E9x3rENlhbVgTj/qdJWZ
fpe3KSW3/tNHkRC/YMJMqsbemTCXdq7gIbyqa28srcEdP8XV2aOCAUQwggFAMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUoIYY
Fvfwa166e3JmMQJ2bQUHQ3MwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzAB
AQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGJBgorBgEEAdZ5AgQC
BHsEeQB3AHUACGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3IAAAGEC4wx
kgAABAMARjBEAiBwdXYiWwZ4VvuEOxStLYhFgX6FsG+3D8kn0kyJrvhBGQIgNxUT
+I+qhBoCGS24ai1YvDfcnZcsBLFPwRNNBcDXm7gwCgYIKoZIzj0EAwMDZwAwZAIw
PO5vrCtwROzycizQctYdGQ1a5iVutbxFg2UrEXW5O+2gtHTrcc4EGITevo8ILPDn
AjAgQz8q59ZTMKwJ0pGFQ3x3jg+Ib2SVVcNhB2kSKTfllnASyT9kgX7MHw/NU1Ow
GMI=
-----END CERTIFICATE-----`;

  describe('when passed a PEM string', () => {
    it('parses a certificate', () => {
      const x = parseCertificate(pem);
      expect(x.serialNumber).toEqual(
        '64C72887AE175785C2712418C09AD7536D948E55'
      );
      expect(x.validFrom).toEqual(new Date('Oct 24 19:50:47 2022 GMT'));
      expect(x.validTo).toEqual(new Date('Oct 24 20:00:47 2022 GMT'));
    });
  });

  describe('when passed a DER byte buffer', () => {
    const der = toDER(pem);

    it('parses a certificate', () => {
      const x = parseCertificate(der);
      expect(x.serialNumber).toEqual(
        '64C72887AE175785C2712418C09AD7536D948E55'
      );
      expect(x.validFrom).toEqual(new Date('Oct 24 19:50:47 2022 GMT'));
      expect(x.validTo).toEqual(new Date('Oct 24 20:00:47 2022 GMT'));
    });
  });
});
