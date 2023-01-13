/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
export const certificates = {
  root: `-----BEGIN CERTIFICATE-----
MIIBzTCCAVOgAwIBAgIUQSFLFi9Qcj7aAn/JIVCBxeAkaEcwCgYIKoZIzj0EAwMw
JjETMBEGA1UECgwKZm9vYmFyLmRldjEPMA0GA1UEAwwGZm9vYmFyMB4XDTkwMDEw
MTAwMDAwMFoXDTQwMDEwMTAwMDAwMFowJjETMBEGA1UECgwKZm9vYmFyLmRldjEP
MA0GA1UEAwwGZm9vYmFyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqOXVeodbskCg
nezXR4wURjSvZjBps6WcqoGP+3DDYhHlZlyniQ1AutSp4oedGA0sfYNjA/FaVoUU
m0QKiYEwtd6oPdkTwDcce/Pq84dR6cz/ue8JMNXEWExf9tRELxpLo0IwQDAdBgNV
HQ4EFgQUW8l0k6NwpkGmRu2O9e3ggYlkc8swDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwPjVLiNY6tLnjCGChiCVSyMg2
jBHKsW++lf0FJZ+XufJAZOrI3nfbUButmomgt0VAAjEAjDa7mLilx7Jx2FoSEVdD
JU/RP8dtt5hUl4GSBmOtv8qfXI0/yCSCjpjMhbMwRixw
-----END CERTIFICATE-----`,

  intermediate: `-----BEGIN CERTIFICATE-----
MIIB8jCCAXigAwIBAgIUUmUzNBkZjzENVRC4bXmkvIH4t3UwCgYIKoZIzj0EAwMw
JjETMBEGA1UECgwKZm9vYmFyLmRldjEPMA0GA1UEAwwGZm9vYmFyMB4XDTkwMDEw
MTAwMDAwMFoXDTQwMDEwMTAwMDAwMFowMzETMBEGA1UECgwKZm9vYmFyLmRldjEc
MBoGA1UEAwwTZm9vYmFyLWludGVybWVkaWF0ZTB2MBAGByqGSM49AgEGBSuBBAAi
A2IABCEnDIqL1KwO/Ux3TZ7T63rf+adOluzCn97SRI1QDzf5jYHIeDbWC9HtYn3U
adlTQ9UfVs9gosSxl9eRLXzSelFnMu/iOg14LT2K2Hg8Mao6txZwhAE5ypAdbHg4
kIZjdqNaMFgwHQYDVR0OBBYEFFbTQbEy5qPGtC/vKCC2cpi5VZDNMA4GA1UdDwEB
/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMD
MAoGCCqGSM49BAMDA2gAMGUCMQDwsfR7Yx4F/oMxt3/h/ik8NIRo1XSjiYwNpbWK
LaAMu35G66UzCi/lSkArwScCsGUCMCpVdFxmvYXTfdg6IMcvxyyNO2ceuxG0XzMW
/VIGo9OSvdkM59VTTQS6KApyqfsOBg==
-----END CERTIFICATE-----`,

  leaf: `-----BEGIN CERTIFICATE-----
MIIB3TCCAWKgAwIBAgIUZAm6agp0Grk4UkwFS/0Cxc/ARdowCgYIKoZIzj0EAwMw
MzETMBEGA1UECgwKZm9vYmFyLmRldjEcMBoGA1UEAwwTZm9vYmFyLWludGVybWVk
aWF0ZTAeFw05MDAxMDEwMDAwMDBaFw00MDAxMDEwMDAwMDBaMAAwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAAS0XnaOtdagbERMAMPIF8llVoOnGIQDQ3aHoY2cNtJm
qZjOUXTV4IOgaOKJIUWJxfZTKiriNHVdpSxtgMOxsOXmo4GGMIGDMB0GA1UdDgQW
BBQfdr4pmKJqGYbuWctaU45J1xjzDDAfBgNVHSMEGDAWgBRW00GxMuajxrQv7ygg
tnKYuVWQzTAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHAYD
VR0RBBUwE4YRaHR0cDovL2Zvb2Jhci5kZXYwCgYIKoZIzj0EAwMDaQAwZgIxAJ2F
kksEb+OXit5GMKU0cGJ9F526A6WSEBbP55k1s0fno1NH6mo34mmVWNL2raz7pgIx
AKTmkrvzqsr4TQ6UHipmYIsRoUfunlYmMZ/7F5o5QeoEFgkgUfgMALdbLlvuWIfw
qA==
-----END CERTIFICATE-----`,

  poisoned: `-----BEGIN CERTIFICATE-----
MIIB0TCCAVegAwIBAgIUEdiHhE/w9Fost4/bgKwoaOHdldUwCgYIKoZIzj0EAwMw
MzETMBEGA1UECgwKZm9vYmFyLmRldjEcMBoGA1UEAwwTZm9vYmFyLWludGVybWVk
aWF0ZTAeFw05MDAxMDEwMDAwMDBaFw00MDAxMDEwMDAwMDBaMAAwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAARubsT3+ifm181AfwfyjgVo2MuOO1AtQMRiTPqUo/0Y
EVE28v+K14Qf6+TMtukEfNc2kQQQ44ypVhpcQbQ0i4YTo3wwejAdBgNVHQ4EFgQU
uDJhmpd0mPW7VSNJ1TFblNbwt8QwHwYDVR0jBBgwFoAUVtNBsTLmo8a0L+8oILZy
mLlVkM0wDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBMGCisG
AQQB1nkCBAMBAf8EAgUAMAoGCCqGSM49BAMDA2gAMGUCMQCT4B2JKP3SjQtu80WU
u0garuiJJzSqxYdlKBAN0304ZcCnpRIyn1R5yCRo2f6UlVYCMH+m2uuicwINsPlL
QHcettKBr/5eWu4DEmBya983E3fB9MlOZ8gYF+UzOJNyvlaTTQ==
-----END CERTIFICATE-----`,

  // Leaf cert w/ no SAN extension
  nosan: `-----BEGIN CERTIFICATE-----
MIIBzzCCAVWgAwIBAgIUdc4zXkJS22Mlt65StmpkV483+BowCgYIKoZIzj0EAwMw
MzETMBEGA1UECgwKZm9vYmFyLmRldjEcMBoGA1UEAwwTZm9vYmFyLWludGVybWVk
aWF0ZTAeFw05MDAxMDEwMDAwMDBaFw00MDAxMDEwMDAwMDBaMAAwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAASgRggQOECzsLeYNRbaoL/u+DhSANDMnSR8V0G0rpFA
3aC8jyR4SEDEJmYcqBWAq6KTHkYXErw1Hed1Q9xQAp0Ao3oweDAdBgNVHQ4EFgQU
jN+PiA9IksHiANhHXEOEAH9giwcwHwYDVR0jBBgwFoAUVtNBsTLmo8a0L+8oILZy
mLlVkM0wDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBEGCisG
AQQBg78wAQEEA0ZPTzAKBggqhkjOPQQDAwNoADBlAjEA1m+8HyhtQIZmjJ73fhLu
MrowOQjIF8zsnRQWhYzbWZRPAyvw+vt3yt3/J+VVsWzwAjB+2Cn/HnK6um0X8NnR
dydvsVlJx6uxwJyljAzgJojn68vWifLuEAdua2I4SvLnqOQ=
-----END CERTIFICATE-----`,

  // Leaf cert with an IP address in the SAN extension.
  badsan: `-----BEGIN CERTIFICATE-----
MIIBzTCCAVOgAwIBAgIUQCLhJFhmBCmElybuK+lDigh1QsowCgYIKoZIzj0EAwMw
MzETMBEGA1UECgwKZm9vYmFyLmRldjEcMBoGA1UEAwwTZm9vYmFyLWludGVybWVk
aWF0ZTAeFw05MDAxMDEwMDAwMDBaFw00MDAxMDEwMDAwMDBaMAAwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAATOgM9B8b8yCn7Po2OAC3oZib/YOhZjmFNuxnKBa+S/
ZqxzIRRO5Sekz/YYAHxuwFoStTe6j0q7wschM1dNLqXho3gwdjAdBgNVHQ4EFgQU
H9J/g613KcOuP/sSYLddP7Dy7MowHwYDVR0jBBgwFoAUVtNBsTLmo8a0L+8oILZy
mLlVkM0wDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA8GA1Ud
EQQIMAaHBMCoAQEwCgYIKoZIzj0EAwMDaAAwZQIwRaBe268A2mF8lHV9b69R97tP
zPPNF63Fdj9wrPMSZaQUI3nHTo5cZeJDnb0jTpC0AjEAjDBzHGK43TnyytQfoKXq
zE7MV8aBKVcaPnltr6Hmqwk9ojQQwy+rscsnxqQPe6CB
-----END CERTIFICATE-----`,

  // Leaf cert w/o a key usage extension.
  nokeyusage: `-----BEGIN CERTIFICATE-----
MIIBvTCCAUOgAwIBAgIUHbYcRH1iTm5sEmh2uY0H8ZxXSUYwCgYIKoZIzj0EAwMw
MzETMBEGA1UECgwKZm9vYmFyLmRldjEcMBoGA1UEAwwTZm9vYmFyLWludGVybWVk
aWF0ZTAeFw05MDAxMDEwMDAwMDBaFw00MDAxMDEwMDAwMDBaMAAwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAASmYOLfOc04n3sK8eR4d3YDvDNhAlVGHqUBU9wS9SZy
apEJK+JrPYgLVxVfrtU1rrQ6ek0yYtRj+BQ9n4yH0fJOo2gwZjAdBgNVHQ4EFgQU
2PyjGOdFS6qKkL7JTSBjwjM7+XUwHwYDVR0jBBgwFoAUVtNBsTLmo8a0L+8oILZy
mLlVkM0wEwYDVR0lBAwwCgYIKwYBBQUHAwMwDwYDVR0RBAgwBocEwKgBATAKBggq
hkjOPQQDAwNoADBlAjEA6VkGzGy2wTzOfM7P4jx4a30rReDN/sDbX00IY7c7SBIK
WiXKqd2GcIDl0cjalAb3AjAdT2sNgcU6XWb4tKz3ZyDdPyMcV0qD+KwoiqIOX1BR
PYfqxucdOUfOslSm08w7zbY=
-----END CERTIFICATE-----`,

  // Leaf cert which was signed by another leaf certificate.
  invalidleaf: `-----BEGIN CERTIFICATE-----
MIIBiTCCAS+gAwIBAgIUfYviXYC9vO06ugkPba8ElSL5pDAwCgYIKoZIzj0EAwMw
ADAeFw05MDAxMDEwMDAwMDBaFw00MDAxMDEwMDAwMDBaMAAwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAT/KWM3bGjsuL+Fi9DgfrM5qljuFtSavihoQKftjsT8U93/
3f/LoSEIbp8uzT85pQrhs9l04BtVMo89q17Zqp4ho4GGMIGDMB0GA1UdDgQWBBSQ
FsfiqIos7CnalmGcDuc/xJtZnDAfBgNVHSMEGDAWgBQfdr4pmKJqGYbuWctaU45J
1xjzDDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHAYDVR0R
BBUwE4YRaHR0cDovL2Zvb2Jhci5kZXYwCgYIKoZIzj0EAwMDSAAwRQIgDmojPO/W
OQ7m6hB+0udxUa+EzeWUnVuVFsDM8BZxM+8CIQDdjO4osDg5Tn9/dWPE8yBLL0ok
v8E/2yJIGKcbArpcsg==
-----END CERTIFICATE-----`,

  fulcioleaf: `-----BEGIN CERTIFICATE-----
MIIDnDCCAyKgAwIBAgIUEg2LbBC+v12QtPBt2jawiYrF33UwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjMwMTExMTczMTUyWhcNMjMwMTExMTc0MTUyWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEscmo8xVdr+olWHVVpTlLdKdTwTDvNpINwLXi
6W2OlPwTkMbJj0zCpO99heNH4ZxF1+NmO6NyjcbynKjf/GPUV6OCAkEwggI9MA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUdsZZ
492PIgVwGjT/q8AwgHhDkj4wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wZAYDVR0RAQH/BFowWIZWaHR0cHM6Ly9naXRodWIuY29tL3NpZ3N0b3JlL3Np
Z3N0b3JlLWpzLy5naXRodWIvd29ya2Zsb3dzL3B1Ymxpc2gueW1sQHJlZnMvdGFn
cy92MC40LjAwOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdp
dGh1YnVzZXJjb250ZW50LmNvbTAVBgorBgEEAYO/MAECBAdyZWxlYXNlMDYGCisG
AQQBg78wAQMEKDhhMmVlMmZkMjBkZGE1OGZmYTRhOGQ4MDhhNjVjYjFlMDQ3MTFj
MDMwFQYKKwYBBAGDvzABBAQHcHVibGlzaDAiBgorBgEEAYO/MAEFBBRzaWdzdG9y
ZS9zaWdzdG9yZS1qczAeBgorBgEEAYO/MAEGBBByZWZzL3RhZ3MvdjAuNC4wMIGK
BgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4py
gC8p7o4AAAGFoeNlfwAABAMARzBFAiBqYOxNKEMS4gXVBqU3Mr/w+yYXYtZDYa6d
aYOZJZB++wIhANat2b2mVTeHERPyhATU/Z8HOfC6iqY/IwiXnwWKsp9xMAoGCCqG
SM49BAMDA2gAMGUCMQD5OzgtStQId/HNXGwVM1Ydjux8x2d4cr7tzWreGSbMUJhR
uVlJliOdJKsu8ufHQfYCMC8M76uThWeCI2A5GndGj0TTaI1Cq92T8oXm5iHHFPxm
vZtjXtnwCuGzLAKHILlmlg==
-----END CERTIFICATE-----`,
};
