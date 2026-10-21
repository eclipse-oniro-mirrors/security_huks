# HUKS<a name="EN-US_TOPIC_0000001148528849"></a>

-   [Introduction](#section11660541593)
-   [Directory Structure](#section161941989596)
-   [Repositories Involved](#section1371113476307)

## Introduction<a name="section11660541593"></a>

OpenHarmony Universal KeyStore \(HUKS\) provides applications with key library capabilities, such as key management and cryptographic operations on keys. HUKS also provides APIs for applications to import or generate keys.

HUKS consists of the following modules:

-   HUKS SDK layer: provides HUKS APIs for applications.

-   HUKS service layer: implements functions such as HUKS key management and storage.
-   HUKS engine layer: HUKS core module, which generates, encrypts, and decrypts keys. For devices running a standard system, this module of the commercial version must run in a secure environment such as a TEE or a chip with security capabilities. A secure environment requires dedicated hardware and is therefore implemented only by emulation in the open-source code. For the small and mini systems, HUKS provides the example implementation of the root key protection solution by default. Only small-system devices built on HiSilicon chips with a built-in hardware cipher engine can enable the hardware-cipher-engine-based root key protection solution through the build option huks_enable_hisilicon_cipher_in_small; this solution requires the board-level huks_cipher_adapter implementation and is unavailable on unadapted devices. In commercial scenarios, the implementation must adapt to the protection solution for either the hardware root key or other root keys.

## Directory Structure<a name="section161941989596"></a>

```
base/security/huks/
├── build                            # Build configuration file
├── frameworks                       # Framework code, which is used by interfaces and services
│   └── huks_standard                # Code implementation
|   └── huks_lite                    # Build script in a small and mini systems
|   └── crypto_lite                  # Encryption and decryption implementation
├── interfaces                       # APIs
│   └── innerkits
│   └── kits
├── services
│   └── huks_standard
├── test
└── utils
   └── crypto_adapter
   └── file_operator
   └── list
   └── mutex
```

## Repositories Involved<a name="section1371113476307"></a>

**Security subsystem**

**[security_huks](https://gitcode.com/openharmony/security_huks)**