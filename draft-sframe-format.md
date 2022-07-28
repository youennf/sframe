---
title: Secure Frame Format (SFrame)
abbrev: SFrame
docname: draft-youennf-sframe-format-01
category: info

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: TBD
    name: T BD
    organization: TBD Inc
    email: t@b.d

informative:
  TestVectors:
    title: "SFrame Test Vectors"
    target: https://github.com/eomara/sframe/blob/master/test-vectors.json
    date: 2021


--- abstract

This document describes the Secure Frame (SFrame) format.
This format can be used for end-to-end encryption and authentication mechanism for media frames, for instance in a multiparty conference call,
in which central media servers (SFUs) can access the media metadata needed to make forwarding decisions without having access to the actual media.

--- middle


# Introduction
Modern multi-party video call systems use Selective Forwarding Unit (SFU) servers to efficiently route RTP streams to call endpoints based on factors such as available bandwidth, desired video size, codec support, and other factors.
In order for the SFU to work properly though, it needs to be able to access RTP metadata and RTCP feedback messages, which is not possible if all RTP/RTCP traffic is end-to-end encrypted.

As such, two layers of encryptions and authentication are required:

  1. Hop-by-hop (HBH) encryption of media, metadata, and feedback messages between the the endpoints and SFU
  2. End-to-end (E2E) encryption of media between the endpoints

While DTLS-SRTP can be used as an efficient HBH mechanism, it is inherently point-to-point and therefore not suitable for a SFU context.

This document proposes a new format to represent encrypted content, called SFrame format, that can be used to build end-to-end encryption designed to work in group conference calls with SFUs.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all
capitals, as shown here.

SFU:
: Selective Forwarding Unit (AKA RTP Switch)

IV:
: Initialization Vector

MAC:
: Message Authentication Code

E2EE:
: End to End Encryption

HBH:
: Hop By Hop

KMS:
: Key Management System

# Goals
The SFrame format is designed to be a suitable E2EE protection scheme for conference call media in a broad range of scenarios, as outlined by the following goals:

1. The SFrame format should allow building secure E2EE mechanism for audio and video in conference calls that can be used with arbitrary SFU servers.

2. The SFrame format should allow decoupling media encryption from key management to allow SFrame format to be used with an arbitrary KMS.

3. The SFrame format should be usable with any underlying transport, be it RTP transports like WebRTC, or non-RTP transports like WebTransport.


# SFrame Format

A processor generating content following the SFrame format takes as input a frame.
A frame can be any arbitrary content: a full video frame, a part of a video frame, an audio chunk, text content...
The content is then encrypted.
A SFrame Header is prepended to the encrypted content to allow proper decryption.
An authentication tag is appended to the encrypted content.

~~~~~
  +------------+------------------------------------------+^+
  |S|LEN|X|KID |         Frame Counter                    | |
+^+------------+------------------------------------------+ |
| |                                                       | |
| |                                                       | |
| |                                                       | |
| |                                                       | |
| |                 Encrypted Content                     | |
| |                                                       | |
| |                                                       | |
| |                                                       | |
| |                                                       | |
+^+-------------------------------------------------------+^+
| |                 Authentication Tag                    | |
| +-------------------------------------------------------+ |
|                                                           |
|                                                           |
+----+Encrypted Portion            Authenticated Portion+---+
~~~~~

# SFrame Header
Each frame will have a unique frame counter that will be used to derive the encryption IV. The frame counter must be unique and monotonically increasing to avoid IV reuse.

As each sender will use their own key for encryption, the SFrame header will include the key id to allow the receiver to identify the key that needs to be used for decrypting.

Both the frame counter and the key id are encoded in a variable length format to decrease the overhead.
The length is up to 8 bytes and is represented in 3 bits in the SFrame header: 000 represents a length of 1, 001 a length of 2...
The first byte in the SFrame header is fixed and contains the header metadata with the following format:

~~~~~
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|R|LEN  |X|  K  |
+-+-+-+-+-+-+-+-+
SFrame header metadata
~~~~~

Reserved (R): 1 bit
    This field MUST be set to zero on sending, and MUST be ignored by receivers.
Counter Length (LEN): 3 bits
    This field indicates the length of the CTR fields in bytes (1-8).
Extended Key Id Flag (X): 1 bit
     Indicates if the key field contains the key id or the key length.
Key or Key Length: 3 bits
     This field contains the key id (KID) if the X flag is set to 0, or the key length (KLEN) if set to 1.

If X flag is 0 then the KID is in the range of 0-7 and the frame counter (CTR) is found in the next LEN bytes:

~~~~~
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+---------------------------------+
|R|LEN  |0| KID |    CTR... (length=LEN)          |
+-+-+-+-+-+-+-+-+---------------------------------+
~~~~~

Frame counter byte length (LEN): 3bits
     The frame counter length in bytes (1-8).
Key id (KID): 3 bits
     The key id (0-7).
Frame counter (CTR): (Variable length)
     Frame counter value up to 8 bytes long.

if X flag is 1 then KLEN is the length of the key (KID), that is found after the SFrame header metadata byte. After the key id (KID), the frame counter (CTR) will be found in the next LEN bytes:

~~~~~
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+---------------------------+---------------------------+
|R|LEN  |1|KLEN |   KID... (length=KLEN)    |    CTR... (length=LEN)    |
+-+-+-+-+-+-+-+-+---------------------------+---------------------------+
~~~~~

Frame counter byte length (LEN): 3bits
     The frame counter length in bytes (1-8).
Key length (KLEN): 3 bits
     The key length in bytes (1-8).
Key id (KID): (Variable length)
     The key id value up to 8 bytes long.
Frame counter (CTR): (Variable length)
     Frame counter value up to 8 bytes long.

# Encryption Schema

SFrame encryption uses an AEAD encryption algorithm and hash function defined by
the ciphersuite in use (see {{ciphersuites}}).  We will refer to the following
aspects of the AEAD algorithm below:

* `AEAD.Encrypt` and `AEAD.Decrypt` - The encryption and decryption functions
  for the AEAD.  We follow the convention of RFC 5116 {{!RFC5116}} and consider
  the authentication tag part of the ciphertext produced by `AEAD.Encrypt` (as
  opposed to a separate field as in SRTP {{?RFC3711}}).

* `AEAD.Nk` - The size of a key for the encryption algorithm, in bytes

* `AEAD.Nn` - The size of a nonce for the encryption algorithm, in bytes

## Key Selection

Each SFrame encryption or decryption operation is premised on a single secret
`base\_key`, which is labeled with an integer KID value signaled in the SFrame
header.

The sender and receivers need to agree on which key should be used for a given
KID.  The process for provisioning keys and their KID values is beyond the scope
of this specification, but its security properties will bound the assurances
that SFrame encryption provides.  For example, if the SFrame format is used to provide E2E
security against intermediary media nodes, then SFrame keys MUST be negotiated in a way
that does not make them accessible to these intermediaries.

For each known KID value, the client stores the corresponding symmetric key
`base\_key`.  For keys that can be used for encryption, the client also stores
the next counter value CTR to be used when encrypting (initially 0).

When encrypting a frame, the application specifies which KID is to be used, and
the counter is incremented after successful encryption.  When decrypting, the
`base\_key` for decryption is selected from the available keys using the KID
value in the SFrame Header.

A given key MUST NOT be used for encryption by multiple senders.  Such reuse
would result in multiple encrypted frames being generated with the same (key,
nonce) pair, which harms the protections provided by many AEAD algorithms.
Implementations SHOULD mark each key as usable for encryption or decryption,
never both.

Note that the set of available keys might change over the lifetime of a
real-time session.  In such cases, the client will need to manage key usage to
avoid media loss due to a key being used to encrypt before all receivers are
able to use it to decrypt.  For example, an application may make decryption-only
keys available immediately, but delay the use of encryption-only keys until (a)
all receivers have acknowledged receipt of the new key or (b) a timeout expires.

## Key Derivation

SFrame encrytion and decryption use a key and salt derived from the `base\_key`
associated to a KID.  Given a `base\_key` value, the key and salt are derived
using HKDF {{!RFC5869}} as follows:

~~~~~
sframe_secret = HKDF-Extract(K, 'SFrame10')
sframe_key = HKDF-Expand(sframe_secret, 'key', AEAD.Nk)
sframe_salt = HKDF-Expand(sframe_secret, 'salt', AEAD.Nn)
~~~~~

The hash function used for HKDF is determined by the ciphersuite in use.

## Encryption

After encoding the frame and before packetizing it, the necessary media metadata
will be moved out of the encoded frame buffer, to be used later in the RTP
generic frame header extension. The encoded frame, the metadata buffer and the
frame counter are passed to SFrame encryptor.

SFrame encryption uses the AEAD encryption algorithm for the ciphersuite in use.
The key for the encryption is the `sframe\_key` and the nonce is formed by XORing
the `sframe\_salt` with the current counter, encoded as a big-endian integer of
length `AEAD.Nn`.

The encryptor forms an SFrame header using the S, CTR, and KID values provided.
The encoded header is provided as AAD to the AEAD encryption operation, with any
frame metadata appended.

~~~~~
def encrypt(S, CTR, KID, frame_metadata, frame):
  sframe_key, sframe_salt = key_store[KID]

  frame_ctr = encode_big_endian(CTR, AEAD.Nn)
  frame_nonce = xor(sframe_salt, frame_ctr)

  header = encode_sframe_header(S, CTR, KID)
  frame_aad = header + frame_metadata

  encrypted_frame = AEAD.Encrypt(sframe_key, frame_nonce, frame_aad, frame)
  return header + encrypted_frame
~~~~~

The encrypted payload is then passed to a generic RTP packetized to construct the RTP packets and encrypt it using SRTP keys for the HBH encryption to the media server.

~~~~~

   +----------------+  +---------------+
   | frame metadata |  |               |
   +-------+--------+  |               |
           |           |     frame     |         
           |           |               |        
           |           |               |         
           |           +-------+-------+        
           |                   |
header ----+------------------>| AAD
+-----+                        |
|  S  |                        |
+-----+                        |
| KID +--+--> sframe_key ----->| Key
|     |  |                     |
|     |  +--> sframe_salt -+   |
+-----+                    |   |
| CTR +--------------------+-->| Nonce
|     |                        |
|     |                        |
+-----+                        |
   |                       AEAD.Encrypt
   |                           |
   |                           V
   |                   +-------+-------+
   |                   |               |
   |                   |               |
   |                   |   encrypted   |
   |                   |     frame     |
   |                   |               |
   |                   |               |
   |                   +-------+-------+
   |                           |        
   |                  generic RTP packetize
   |                           |           
   |                           v           
   V                                       
+---------------+      +---------------+     +---------------+
| SFrame header |      |               |     |               |
+---------------+      |               |     |               |
|               |      |  payload 2/N  |     |  payload N/N  |
|  payload 1/N  |      |               |     |               |
|               |      |               |     |               |
+---------------+      +---------------+     +---------------+
~~~~~
{: title="Encryption flow" }

## Decryption

The receiving clients buffer all packets that belongs to the same frame using the frame beginning and ending marks in the generic RTP frame header extension, and once all packets are available, it passes it to SFrame for decryption.  The KID field in the SFrame header is used to find the right key for the encrypted frame.

~~~~~
def decrypt(frame_metadata, sframe):
  header, encrypted_frame = split_header(sframe)
  S, CTR, KID = parse_header(header)

  sframe_key, sframe_salt = key_store[KID]

  frame_ctr = encode_big_endian(CTR, AEAD.Nn)
  frame_nonce = xor(sframe_salt, frame_ctr)
  frame_aad = header + frame_metadata

  return AEAD.Decrypt(sframe_key, frame_nonce, frame_aad, encrypted_frame)
~~~~~

For frames that are failed to decrypt because there is key available for the KID in the SFrame header, the client MAY buffer the frame and retry decryption once a key with that KID is received.

### Duplicate Frames
Unlike messaging application, in video calls, receiving a duplicate frame doesn't necessary mean the client is under a replay attack, there are other reasons that might cause this, for example the sender might just be sending them in case of packet loss. SFrame decryptors use the highest received frame counter to protect against this. It allows only older frame pithing a short interval to support out of order delivery.

# Ciphersuites

Each SFrame session uses a single ciphersuite that specifies the following primitives:

o A hash function used for key derivation and hashing signature inputs

o An AEAD encryption algorithm [RFC5116] used for frame encryption, optionally
  with a truncated authentication tag

o [Optional] A signature algorithm

This document defines the following ciphersuites:


| Value  | Name                           | Nh | Nk | Nn | Reference |
|:-------|:-------------------------------|:---|:---|:---|:----------|
| 0x0001 | AES\_CM\_128\_HMAC\_SHA256\_8  | 32 | 16 | 12 | RFC XXXX  |
| 0x0002 | AES\_CM\_128\_HMAC\_SHA256\_4  | 32 | 16 | 12 | RFC XXXX  |
| 0x0003 | AES\_GCM\_128\_SHA256          | 32 | 16 | 12 | RFC XXXX  |
| 0x0004 | AES\_GCM\_256\_SHA512          | 64 | 32 | 12 | RFC XXXX  |

<!-- RFC EDITOR: Please replace XXXX above with the RFC number assigned to this
document -->

In the "AES\_CM" suites, the length of the authentication tag is indicated by
the last value: "\_8" indicates an eight-byte tag and "\_4" indicates a
four-byte tag.

In a session that uses multiple media streams, different ciphersuites might be
configured for different media streams.  For example, in order to conserve
bandwidth, a session might use a ciphersuite with 80-bit tags for video frames
and another ciphersuite with 32-bit tags for audio frames.

## AES-CM with SHA2

In order to allow very short tag sizes, we define a synthetic AEAD function
using the authenticated counter mode of AES together with HMAC for
authentication.  We use an encrypt-then-MAC approach as in SRTP {{?RFC3711}}.

Before encryption or decryption, encryption and authentication subkeys are
derived from the single AEAD key using HKDF.  The subkeys are derived as
follows, where `Nk` represents the key size for the AES block cipher in use and
`Nh` represents the output size of the hash function:

~~~~~
def derive_subkeys(sframe_key):
  aead_secret = HKDF-Extract(sframe_key, 'SFrame10 AES CM AEAD')
  enc_key = HKDF-Expand(aead_secret, 'enc', Nk)
  auth_key = HKDF-Expand(aead_secret, 'auth', Nh)
  return enc_key, auth_key
~~~~~

The AEAD encryption and decryption functions are then composed of individual
calls to the CM encrypt function and HMAC.  The resulting MAC value is truncated
to a number of bytes `tag_len` fixed by the ciphersuite.

~~~~~
def compute_tag(auth_key, nonce, aad, ct):
  aad_len = encode_big_endian(len(aad), 8)
  ct_len = encode_big_endian(len(ct), 8)
  auth_data = aad_len + ct_len + nonce + aad + ct
  tag = HMAC(auth_key, auth_data)
  return truncate(tag, tag_len)

def AEAD.Encrypt(key, nonce, aad, pt):
  enc_key, auth_key = derive_subkeys(key)
  ct = AES-CM.Encrypt(enc_key, nonce, pt)
  tag = compute_tag(auth_key, nonce, aad, ct)
  return ct + tag

def AEAD.Decrypt(key, nonce, aad, ct):
  inner_ct, tag = split_ct(ct, tag_len)

  enc_key, auth_key = derive_subkeys(key)
  candidate_tag = compute_tag(auth_key, nonce, aad, inner_ct)
  if !constant_time_equal(tag, candidate_tag):
    raise Exception("Authentication Failure")

  return AES-CM.Decrypt(enc_key, nonce, inner_ct)
~~~~~

# Overhead
The encryption overhead will vary depending on how content is split into frames.
The number of bytes overhead per frame is calculated as the following
1 + FrameCounter length + 4
The constant 1 is the SFrame header byte and 4 bytes for the HBH authentication tag.

# Security Considerations

## No Per-Sender Authentication

SFrame does not provide per-sender authentication of media data. Any sender in a session can send media that will be associated with any other sender.
This is because SFrame uses symmetric encryption to protect media data, so that any receiver also has the keys required to encrypt packets for the sender.

## Key Management
Key exchange mechanism is out of scope of this document, however every client is expected to change their keys when new clients joins or leaves the call for "Forward Secrecy" and "Post Compromise Security".

## Authentication tag length
The cipher suites defined in this draft use short authentication tags for encryption, however it can easily support other ciphers with full authentication tag if the short ones are proved insecure.

# IANA Considerations
This document makes no requests of IANA.

# Acknowledgements

   The authors wish to specially thank Dr. Alex Gouaillard as one of the early contributors to the document. His passion and energy were key to the design and development of SFrame. 

# Test Vectors

This section provides a set of test vectors that implementations can use to
verify that they correctly implement SFrame encryption and decryption.  For each
ciphersuite, we provide:

* [in] The `base_key` value (hex encoded)
* [out] The `secret`, `key`, and `salt` values derived from the `base_key` (hex encoded)
* A plaintext value that is encrypted in the following encryption cases
* A sequence of encryption cases, including:
  * [in] The `KID` and `CTR` values to be included in the header
  * [out] The resulting encoded header (hex encoded)
  * [out] The nonce computed from the `salt` and `CTR` values
  * The ciphertext resulting from encrypting the plaintext with these parameters
    (hex encoded)

An implementation should reproduce the output values given the input values:
* An implementation should be able to encrypt with the input values and the plaintext to produce the ciphertext.
* An implementation must be able to decrypt with the input values and the ciphertext to generate the plaintext.

Line breaks and whitespace within values are inserted to conform to the width
requirements of the RFC format.  They should be removed before use.
These test vectors are also available in JSON format at {{TestVectors}}.

{::include test-vectors.md}
