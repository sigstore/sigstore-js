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
///////////////////////////////////////////////////////////////////////////////
// VALID BUNDLES
///////////////////////////////////////////////////////////////////////////////

// Valid messageSignature bundle signed with a Fulcio signing certificate
const validBundleWithSigningCert = {
  mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
  verificationMaterial: {
    x509CertificateChain: {
      certificates: [
        {
          rawBytes:
            'MIICoDCCAiagAwIBAgIUevae+nLQ8mg6OyOB43MKJ10F2CEwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjIxMTA5MDEzMzA5WhcNMjIxMTA5MDE0MzA5WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9DbYBIMQLtWb6J5gtL69jgRwwEfdtQtKvvG4+o3ZzlOroJplpXaVgF6wBDob++rNG9/AzSaBmApkEwI52XBjWqOCAUUwggFBMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUVIIFc08z6uV9Y96S+v5oDbbmHEYwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzABAQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGEWgUGQwAABAMARzBFAiEAlKycMBC2q+QM+mct60RNENxpURHes6vgOBWdx71XcXgCIAtnMzw/cBw5h0hrYJ8b1PJjoxn3k1N2TdgofqvMhbSTMAoGCCqGSM49BAMDA2gAMGUCMQC2KLFYSiD/+S1WEsyf9czf52w+E577Hi77r8pGUM1rQ/Bzg1aGvQs0/kAg3S/JSDgCMEdN5dIS0tRm1SOMbOFcW+1yzR+OiCVJ7DVFwUdI3D/7ERxtN9e/LJ6uaRnR/Sanrw==',
        },
      ],
    },
    publicKey: undefined,
    tlogEntries: [
      {
        logIndex: '6757503',
        logId: { keyId: 'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=' },
        kindVersion: { kind: 'hashedrekord', version: '0.0.1' },
        integratedTime: '1667957590',
        inclusionPromise: undefined,
        inclusionProof: {
          logIndex: '2594072',
          rootHash: 'kAnoYYy8iB3NjC5tE2l6pGBqY3uw3CBJ6x2cBBQXu0U=',
          treeSize: '22954907',
          hashes: [
            'qEpgYkIiW7jVzbHp54MraVJQ1AE72Zvr5XSohvcdBN4=',
            'wtdXKmzwBO1Lr1bY5gOXpVUiP0OxYRRa9ZodfVYRKw8=',
            'ikD2dl7XVH3EKAPc6k21SYog5TYdwp/8DayXZ8Eedtw=',
            '3oHeiTXTqKZMOpundZhKh4c6dznt7SdFj88Gog5DCYY=',
            '4By9NfYQqHZOn5CusfRqIGw9/NeQr5E1nG4ICulNnUo=',
            'p3BgRy0uSg6SRAqcKt8qXUIDhhJhox1tCAIaHdT5tac=',
            'lJvUc0jjih3wNA1S7cbtw1q5HYX3JxYY5fO9ytPIKLU=',
            '5vWL6hRP9EBDNAuXS3E236YUwutNv6qvIWTfcdzywFA=',
            '1ODC3wToc5Hqky2sJQ2w3mBFggDWdZROOAv4MXWWLw0=',
            'QqwionvWKT5a3Kqsx1UWIYDsBIMK7H+pvKZNon1g4A4=',
            '9Ckxujk8Sg094zTRpBWmwd4ZWNT7W72H/S2JPKbZiBY=',
            '/gKT0/YRP2WbANUct+sWMGGQ2a9lQlNFBb/XYAhb/j8=',
            'f+eeYNJFCZRAI6IKsab+xTmMUl9g6Km2h6KUztMHpxM=',
            'P8eLjDLaNzX9cTdqiFIKYjyVJv4cNwxPBh1Ppg8eDvM=',
            '7NR456rTv4HEGWxCwUOTYm7ze69yMkqG4f8MbhE43oU=',
            'Ul2YswjUyBqbJ3eka2zE0MI0QxT4ez8sCJ1Z3+vvMw8=',
            'ucRPSmGLhm/SyHL7chQ5vBEFull08HzsqtAC0TQ91tY=',
            'EiS8ntcvGnB1xcGZg9Cf3fTkV1wBcJNVtSWKIYVZqAU=',
            'Mx1LEx7szsPd62CGkL6HM+NWkOy9YwZTwukJEVgH7Cw=',
            's2Z13KVYurVY6F1AUhr8Uby4RE3RXW1XEC2tWWdzCjI=',
            'QRfYxLEHh/FwMZqWnxNNW+x3lY7o3LM86BW+z0MpMN4=',
            'J0dGjQ7V5bETi7p7eWg2ephCQ32QBLMWY5HxFcuGfR4=',
            'uFGzOQorMYmYZ2yumLpgr1tvXvZaL+tTTCqaXa7Hdds=',
            'Lksw/hm/y+1p33SaEF8/60gPvFVNkueBpDWJ1tAVcAo=',
            'o4Smg8NUiGzxKxvvvgjtH2NV82EZSBLcUDUo9IpzS0Y=',
          ],
          checkpoint: {
            envelope:
              'rekor.sigstore.dev - 2605736670972794746\n22954907\nkAnoYYy8iB3NjC5tE2l6pGBqY3uw3CBJ6x2cBBQXu0U=\nTimestamp: 1689107716054191855\n\n— rekor.sigstore.dev wNI9ajBFAiEA8OpuifHq4iqd6ZJSRiVQbe00eTdZllaQ51fgfAVxAPkCIDC64vV4bCtkn3S8CyMaTHHWgD2E/a+nm0eFBADK/LFP\n',
          },
        },
        canonicalizedBody:
          'eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2OGU2NTZiMjUxZTY3ZTgzNThiZWY4NDgzYWIwZDUxYzY2MTlmM2U3YTFhOWYwZTc1ODM4ZDQxZmYzNjhmNzI4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJSHM1YVV1bHExSHBSK2Z3bVNLcExrL29Bd3E1TzlDRE5GSGhaQUtmRzVHbUFpQndjVm5mMm9ienNDR1ZsZjBBSXZidkhyMjFOWHQ3dHBMQmw0K0JyaDZPS0E9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTnZSRU5EUVdsaFowRjNTVUpCWjBsVlpYWmhaU3R1VEZFNGJXYzJUM2xQUWpRelRVdEtNVEJHTWtORmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcEplRTFVUVRWTlJFVjZUWHBCTlZkb1kwNU5ha2w0VFZSQk5VMUVSVEJOZWtFMVYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVU1UkdKWlFrbE5VVXgwVjJJMlNqVm5kRXcyT1dwblVuZDNSV1prZEZGMFMzWjJSelFLSzI4elducHNUM0p2U25Cc2NGaGhWbWRHTm5kQ1JHOWlLeXR5VGtjNUwwRjZVMkZDYlVGd2EwVjNTVFV5V0VKcVYzRlBRMEZWVlhkblowWkNUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZXU1VsR0NtTXdPSG8yZFZZNVdUazJVeXQyTlc5RVltSnRTRVZaZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBoM1dVUldVakJTUVZGSUwwSkNWWGRGTkVWU1dXNUtjRmxYTlVGYVIxWnZXVmN4YkdOcE5XcGlNakIzVEVGWlMwdDNXVUpDUVVkRWRucEJRZ3BCVVZGbFlVaFNNR05JVFRaTWVUbHVZVmhTYjJSWFNYVlpNamwwVERKNGRsb3liSFZNTWpsb1pGaFNiMDFKUjB0Q1oyOXlRbWRGUlVGa1dqVkJaMUZEQ2tKSWQwVmxaMEkwUVVoWlFUTlVNSGRoYzJKSVJWUktha2RTTkdOdFYyTXpRWEZLUzFoeWFtVlFTek12YURSd2VXZERPSEEzYnpSQlFVRkhSVmRuVlVjS1VYZEJRVUpCVFVGU2VrSkdRV2xGUVd4TGVXTk5Ra015Y1N0UlRTdHRZM1EyTUZKT1JVNTRjRlZTU0dWek5uWm5UMEpYWkhnM01WaGpXR2REU1VGMGJncE5lbmN2WTBKM05XZ3dhSEpaU2poaU1WQkthbTk0YmpOck1VNHlWR1JuYjJaeGRrMW9ZbE5VVFVGdlIwTkRjVWRUVFRRNVFrRk5SRUV5WjBGTlIxVkRDazFSUXpKTFRFWlpVMmxFTHl0VE1WZEZjM2xtT1dONlpqVXlkeXRGTlRjM1NHazNOM0k0Y0VkVlRURnlVUzlDZW1jeFlVZDJVWE13TDJ0Qlp6TlRMMG9LVTBSblEwMUZaRTQxWkVsVE1IUlNiVEZUVDAxaVQwWmpWeXN4ZVhwU0swOXBRMVpLTjBSV1JuZFZaRWt6UkM4M1JWSjRkRTQ1WlM5TVNqWjFZVkp1VWdvdlUyRnVjbmM5UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PSJ9fX19',
      },
    ],
    timestampVerificationData: { rfc3161Timestamps: [] },
  },
  messageSignature: {
    messageDigest: {
      algorithm: 'SHA2_256',
      digest: 'aOZWslHmfoNYvvhIOrDVHGYZ8+ehqfDnWDjUH/No9yg=',
    },
    signature:
      'MEQCIHs5aUulq1HpR+fwmSKpLk/oAwq5O9CDNFHhZAKfG5GmAiBwcVnf2obzsCGVlf0AIvbvHr21NXt7tpLBl4+Brh6OKA==',
  },
  dsseEnvelope: undefined,
};

// Valid messageSignature bundle signed with a public key
const validBundleWithPublicKey = {
  mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
  verificationMaterial: {
    publicKey: {
      hint: '9a76331edc1cfd3933040996615b1c06adbe6f9b4f11df4106dcceb66e3bdb1b',
    },
    tlogEntries: [
      {
        logIndex: '6757503',
        logId: { keyId: 'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=' },
        kindVersion: { kind: 'hashedrekord', version: '0.0.1' },
        integratedTime: '1667957590',
        inclusionPromise: undefined,
        inclusionProof: {
          logIndex: '2594072',
          rootHash: 'kAnoYYy8iB3NjC5tE2l6pGBqY3uw3CBJ6x2cBBQXu0U=',
          treeSize: '22954907',
          hashes: [
            'qEpgYkIiW7jVzbHp54MraVJQ1AE72Zvr5XSohvcdBN4=',
            'wtdXKmzwBO1Lr1bY5gOXpVUiP0OxYRRa9ZodfVYRKw8=',
            'ikD2dl7XVH3EKAPc6k21SYog5TYdwp/8DayXZ8Eedtw=',
            '3oHeiTXTqKZMOpundZhKh4c6dznt7SdFj88Gog5DCYY=',
            '4By9NfYQqHZOn5CusfRqIGw9/NeQr5E1nG4ICulNnUo=',
            'p3BgRy0uSg6SRAqcKt8qXUIDhhJhox1tCAIaHdT5tac=',
            'lJvUc0jjih3wNA1S7cbtw1q5HYX3JxYY5fO9ytPIKLU=',
            '5vWL6hRP9EBDNAuXS3E236YUwutNv6qvIWTfcdzywFA=',
            '1ODC3wToc5Hqky2sJQ2w3mBFggDWdZROOAv4MXWWLw0=',
            'QqwionvWKT5a3Kqsx1UWIYDsBIMK7H+pvKZNon1g4A4=',
            '9Ckxujk8Sg094zTRpBWmwd4ZWNT7W72H/S2JPKbZiBY=',
            '/gKT0/YRP2WbANUct+sWMGGQ2a9lQlNFBb/XYAhb/j8=',
            'f+eeYNJFCZRAI6IKsab+xTmMUl9g6Km2h6KUztMHpxM=',
            'P8eLjDLaNzX9cTdqiFIKYjyVJv4cNwxPBh1Ppg8eDvM=',
            '7NR456rTv4HEGWxCwUOTYm7ze69yMkqG4f8MbhE43oU=',
            'Ul2YswjUyBqbJ3eka2zE0MI0QxT4ez8sCJ1Z3+vvMw8=',
            'ucRPSmGLhm/SyHL7chQ5vBEFull08HzsqtAC0TQ91tY=',
            'EiS8ntcvGnB1xcGZg9Cf3fTkV1wBcJNVtSWKIYVZqAU=',
            'Mx1LEx7szsPd62CGkL6HM+NWkOy9YwZTwukJEVgH7Cw=',
            's2Z13KVYurVY6F1AUhr8Uby4RE3RXW1XEC2tWWdzCjI=',
            'QRfYxLEHh/FwMZqWnxNNW+x3lY7o3LM86BW+z0MpMN4=',
            'J0dGjQ7V5bETi7p7eWg2ephCQ32QBLMWY5HxFcuGfR4=',
            'uFGzOQorMYmYZ2yumLpgr1tvXvZaL+tTTCqaXa7Hdds=',
            'Lksw/hm/y+1p33SaEF8/60gPvFVNkueBpDWJ1tAVcAo=',
            'o4Smg8NUiGzxKxvvvgjtH2NV82EZSBLcUDUo9IpzS0Y=',
          ],
          checkpoint: {
            envelope:
              'rekor.sigstore.dev - 2605736670972794746\n22954907\nkAnoYYy8iB3NjC5tE2l6pGBqY3uw3CBJ6x2cBBQXu0U=\nTimestamp: 1689107716054191855\n\n— rekor.sigstore.dev wNI9ajBFAiEA8OpuifHq4iqd6ZJSRiVQbe00eTdZllaQ51fgfAVxAPkCIDC64vV4bCtkn3S8CyMaTHHWgD2E/a+nm0eFBADK/LFP\n',
          },
        },
        canonicalizedBody:
          'eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2OGU2NTZiMjUxZTY3ZTgzNThiZWY4NDgzYWIwZDUxYzY2MTlmM2U3YTFhOWYwZTc1ODM4ZDQxZmYzNjhmNzI4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJSHM1YVV1bHExSHBSK2Z3bVNLcExrL29Bd3E1TzlDRE5GSGhaQUtmRzVHbUFpQndjVm5mMm9ienNDR1ZsZjBBSXZidkhyMjFOWHQ3dHBMQmw0K0JyaDZPS0E9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTnZSRU5EUVdsaFowRjNTVUpCWjBsVlpYWmhaU3R1VEZFNGJXYzJUM2xQUWpRelRVdEtNVEJHTWtORmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcEplRTFVUVRWTlJFVjZUWHBCTlZkb1kwNU5ha2w0VFZSQk5VMUVSVEJOZWtFMVYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVU1UkdKWlFrbE5VVXgwVjJJMlNqVm5kRXcyT1dwblVuZDNSV1prZEZGMFMzWjJSelFLSzI4elducHNUM0p2U25Cc2NGaGhWbWRHTm5kQ1JHOWlLeXR5VGtjNUwwRjZVMkZDYlVGd2EwVjNTVFV5V0VKcVYzRlBRMEZWVlhkblowWkNUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZXU1VsR0NtTXdPSG8yZFZZNVdUazJVeXQyTlc5RVltSnRTRVZaZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBoM1dVUldVakJTUVZGSUwwSkNWWGRGTkVWU1dXNUtjRmxYTlVGYVIxWnZXVmN4YkdOcE5XcGlNakIzVEVGWlMwdDNXVUpDUVVkRWRucEJRZ3BCVVZGbFlVaFNNR05JVFRaTWVUbHVZVmhTYjJSWFNYVlpNamwwVERKNGRsb3liSFZNTWpsb1pGaFNiMDFKUjB0Q1oyOXlRbWRGUlVGa1dqVkJaMUZEQ2tKSWQwVmxaMEkwUVVoWlFUTlVNSGRoYzJKSVJWUktha2RTTkdOdFYyTXpRWEZLUzFoeWFtVlFTek12YURSd2VXZERPSEEzYnpSQlFVRkhSVmRuVlVjS1VYZEJRVUpCVFVGU2VrSkdRV2xGUVd4TGVXTk5Ra015Y1N0UlRTdHRZM1EyTUZKT1JVNTRjRlZTU0dWek5uWm5UMEpYWkhnM01WaGpXR2REU1VGMGJncE5lbmN2WTBKM05XZ3dhSEpaU2poaU1WQkthbTk0YmpOck1VNHlWR1JuYjJaeGRrMW9ZbE5VVFVGdlIwTkRjVWRUVFRRNVFrRk5SRUV5WjBGTlIxVkRDazFSUXpKTFRFWlpVMmxFTHl0VE1WZEZjM2xtT1dONlpqVXlkeXRGTlRjM1NHazNOM0k0Y0VkVlRURnlVUzlDZW1jeFlVZDJVWE13TDJ0Qlp6TlRMMG9LVTBSblEwMUZaRTQxWkVsVE1IUlNiVEZUVDAxaVQwWmpWeXN4ZVhwU0swOXBRMVpLTjBSV1JuZFZaRWt6UkM4M1JWSjRkRTQ1WlM5TVNqWjFZVkp1VWdvdlUyRnVjbmM5UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PSJ9fX19',
      },
    ],
    timestampVerificationData: { rfc3161Timestamps: [] },
  },
  messageSignature: {
    messageDigest: {
      algorithm: 'SHA2_256',
      digest: 'aOZWslHmfoNYvvhIOrDVHGYZ8+ehqfDnWDjUH/No9yg=',
    },
    signature:
      'MEQCIHs5aUulq1HpR+fwmSKpLk/oAwq5O9CDNFHhZAKfG5GmAiBwcVnf2obzsCGVlf0AIvbvHr21NXt7tpLBl4+Brh6OKA==',
  },
};

export default {
  artifact: Buffer.from('hello, world!'),
  valid: {
    withSigningCert: validBundleWithSigningCert,
    withPublicKey: validBundleWithPublicKey,
  },
  invalid: {},
};
