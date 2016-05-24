---
title: Using Transport Layer Security (TLS) to Secure QUIC
abbrev: QUIC over TLS
docname: draft-thomson-quic-tls-latest
date: 2016
category: std
ipr: trust200902

stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    org: Mozilla
    email: martin.thomson@gmail.com
 -
    ins: R. Hamilton
    name: Ryan Hamilton
    org: Google
    email: rch@google.com


normative:
  RFC2119:
  RFC5116:
  I-D.ietf-tls-tls13:
  I-D.tsvwg-quic-protocol:
  RFC7301:

informative:
  RFC7540:
  RFC7230:
  RFC7258:
  RFC0793:
  I-D.ietf-tls-cached-info:
  RFC7685:

--- abstract

This document describes how Transport Layer Security (TLS) can be used to secure
QUIC.


--- middle

# Introduction

QUIC [I-D.tsvwg-quic-protocol] provides a multiplexed transport for HTTP
[RFC7230] semantics that provides several key advantages over HTTP/1.1 [RFC7230]
or HTTP/2 [RFC7540] over TCP [RFC0793].

This document describes how QUIC can be secured using Transport Layer Security
(TLS) version 1.3 [I-D.ietf-tls-tls13].  TLS 1.3 provides critical latency
improvements for connection establishment over previous versions.  Absent packet
loss, most new connections can be established and secured within a single round
trip; on subsequent connections between the same client and server, the client
can often send application data immediately, that is, zero round trip setup.

This document describes how the standardized TLS 1.3 can act a security
component of QUIC.  The same design could work for TLS 1.2, though few of the
benefits QUIC provides would be realized due to the handshake latency in
versions of TLS prior to 1.3.


## Notational Conventions

The words "MUST", "MUST NOT", "SHOULD", and "MAY" are used in this document.
It's not shouting; when they are capitalized, they have the special meaning
defined in [RFC2119].


# Protocol Overview

QUIC [I-D.tsvwg-quic-protocol] can be separated into several modules:

1. The basic frame envelope describes the common packet layout.  This layer
   includes connection identification, version negotiation, and includes the
   indicators that allow the framing, and public reset packets to be
   identified.

2. The public reset is an unprotected packet that allows an intermediary (an
   entity that is not part of the security context) to request the termination
   of a QUIC connection.

3. Version negotiation frames are used to agree on a common version of QUIC to
   use.

4. Framing comprises most of the QUIC protocol.  Framing provides a number of
   different types of frame, each with a specific purpose.  Framing supports
   frames for both congestion management and stream multiplexing.  Framing
   additionally provides a liveness testing capability (the PING frame).

5. Encryption provides confidentiality and integrity protection for frames.  All
   frames are protected based on keying material derived from the TLS connection
   running on stream 1.  Prior to this, data is protected with the 0-RTT keys.
   (TODO: Explain that crypto handshake messages are null encrypted. This is
   some what explained in point 8?)

6. Multiplexed streams are the primary payload of QUIC.  These provide reliable,
   in-order delivery of data and are used to carry the encryption handshake and
   transport parameters (stream 1), HTTP header fields (stream 3), and HTTP
   requests and responses.  Frames for managing multiplexing include those for
   creating and destroying streams as well as flow control and priority frames.

7. Congestion management includes packet acknowledgment and other signal
   required to ensure effective use of available link capacity.

8. A complete TLS connection is run on stream 1.  This includes the entire TLS
   record layer.  As the TLS connection reaches certain states, keying material
   is provided to the QUIC encryption layer for protecting the remainder of the
   QUIC traffic.

9. HTTP mapping provides an adaptation to HTTP that is based on HTTP/2.

The relative relationship of these components are pictorally represented in
{{quic-structure}}.

~~~
   +-----+------+
   | TLS | HTTP |
   +-----+------+------------+
   |  Streams   | Congestion |
   +------------+------------+
   |        Frames           +--------+---------+
   +   +---------------------+ Public | Version |
   |   |     Encryption      | Reset  |  Nego.  |
   +---+---------------------+--------+---------+
   |                   Envelope                 |
   +--------------------------------------------+
   |                     UDP                    |
   +--------------------------------------------+
~~~
{: #quic-structure title="QUIC Structure"}

This document defines the cryptographic parts of QUIC.  This includes the
handshake messages that are exchanged on stream 1, plus the record protection
that is used to encrypt and authenticate all other frames.


## Handshake Overview

TLS 1.3 provides two basic handshake modes of interest to QUIC:

 * A full handshake in which the client is able to send application data after
   one round trip and the server immediately after receiving the first message
   from the client.

 * A 0-RTT handshake in which the client uses information about the server to
   send immediately.  This data can be replayed by an attacker so it MUST NOT
   carry a self-contained trigger for any non-idempotent action.

A simplified TLS 1.3 handshake with 0-RTT application data is shown in
{{tls-full}}, see [I-D.ietf-tls-tls13] for more options and details.

~~~
    Client                                             Server

    ClientHello
   (Finished)
   (0-RTT Application Data)
   (end_of_early_data)        -------->
                                                  ServerHello
                                         {EncryptedExtensions}
                                         {ServerConfiguration}
                                                 {Certificate}
                                           {CertificateVerify}
                                                    {Finished}
                             <--------      [Application Data]
   {Finished}                -------->

   [Application Data]        <------->      [Application Data]
~~~
{: #tls-full title="TLS Handshake with 0-RTT"}

Two additional variations on this basic handshake exchange are relevant to this
document:

 * The server can respond to a ClientHello with a HelloRetryRequest, which adds
   an additional round trip prior to the basic exchange.  This is needed if the
   server wishes to request a different key exchange key from the client.
   HelloRetryRequest is also used to verify that the client is correctly able to
   receive packets on the address it claims to have (see {{source-address}}).

 * A pre-shared key mode can be used for subsequent handshakes to avoid public
   key operations.  This is the basis for 0-RTT data, even if the remainder of
   the connection is protected by a new Diffie-Hellman exchange.


# TLS in Stream 1

QUIC completes its cryptographic handshake on stream 1, which means that the
negotiation of keying material happens after the QUIC protocol has started.
This simplifies the use of TLS since QUIC is able to ensure that the TLS
handshake packets are delivered reliably and in order.

QUIC Stream 1 carries a complete TLS connection.  This includes the TLS record
layer in its entirety.  QUIC provides for reliable and in-order delivery of the
TLS handshake messages on this stream.

Prior to the completion of the TLS handshake, QUIC frames can be exchanged.
However, these frames are not authenticated or confidentiality protected.
{{pre-handshake}} covers some of the implications of this design and limitations
on QUIC operation during this phase.

Once complete, QUIC frames are protected using QUIC record protection, see
{{record-protection}}.


## Handshake and Setup Sequence

The integration of QUIC with a TLS handshake is shown in more detail in
{{quic-tls-handshake}}.  QUIC `STREAM` frames on stream 1 carry the TLS
handshake.  QUIC is responsible for ensuring that the handshake packets are
re-sent in case of loss and that they can be ordered correctly.

~~~
    Client                                             Server

   QUIC STREAM Frame(s) <1>:
     ClientHello
       + QUIC Setup Parameters
                            -------->
 ! 0-RTT Key Available

   (QUIC STREAM Frame(s) <1>:)
     ({Finished})
   (Replayable QUIC Frames <any stream>)
                            -------->
                                           0-RTT Key Available !

                                      (QUIC STREAM Frame <1>:)
                                               (ServerHello)
                                      ({Handshake Messages})
                            <--------
                                           1-RTT Key Available !

                                                 [QUIC Frames]
                            <--------
   (QUIC STREAM Frame(s) <1>:)
     ((end_of_early_data <1>))
     ({Finished})
                            -------->
 ! 1-RTT Key Available

   [QUIC Frames]            <------->            [QUIC Frames]
~~~
{: #quic-tls-handshake title="QUIC over TLS Handshake"}

In {{quic-tls-handshake}}, symbols mean:

* "<" and ">" enclose stream numbers.
* "!" indicates when keying material is available.
* "(" and ")" enclose messages that are protected with QUIC or TLS 0-RTT keys.
  If 0-RTT is not possible, or not accepted, then regular frames protected by
  this keys are not sent by the client, and the server sends its handshake
  messages without protection.
* "{" and "}" enclose messages that are protected by the TLS Handshake
  keys. Note that the client's 0-RTT Finished message is protected by the QUIC
  0-RTT key, plus the TLS 0-RTT handshake key.
* "[" and "]" enclose messages that are protected by the QUIC 1-RTT keys.


# QUIC Record Protection {#record-protection}

QUIC provides a record protection layer that is responsible for authenticated
encryption of packets.  The record protection layer uses keys provided by the
TLS connection and authenticated encryption to provide confidentiality and
integrity protection for the content of packets.

Different keys are used for QUIC and TLS record protection.  Having separate
QUIC and TLS record protection means that TLS records can be protected by two
different keys.  This redundancy is maintained for the sake of simplicity.


## Key Phases

The transition to use of a new QUIC key occurs immediately after sending the TLS
handshake messages that produced the key transition.  Every time that a new set
of keys is used for protecting outbound messages, the KEY_PHASE bit in the
public flags is toggled.  The KEY_PHASE bit on unencrypted messages is 0.

The KEY_PHASE bit on the public flags is the most significant bit (0x80).

The KEY_PHASE bit allows a recipient to detect a change in keying material
without needing to receive the message that triggers the change.  This avoids
head-of-line blocking around transitions between keys without relying on trial
decryption.

The following transitions are defined:

* The client transitions to using 0-RTT keys after sending the ClientHello.
  This causes the KEY_PHASE bit on packets sent by the client to be set to 1.

* The server transitions to using 0-RTT keys before sending the ServerHello, but
  only if the early data from the client is accepted.  This transition causes
  the KEY_PHASE bit on packets sent by the server to be set to 1.  If the server
  rejects 0-RTT data, the server's handshake messages are sent without
  QUIC-level record protection with a KEY_PHASE of 0.  TLS handshake messages
  will still be protected by TLS record protection based on the TLS handshake
  traffic keys.

* The server transitions to using 1-RTT keys after sending its Finished message.
  This causes the KEY_PHASE bit to be set to 0 if early data was accepted, and 1
  if the server rejected early data.

* The client transitions to 1-RTT keys after sending its Finished message.
  Subsequent messages from the client will then have a KEY_PHASE of 0 if 0-RTT
  data was sent, and 1 otherwise.

* Both peers start sending messages protected by a new key immediately after
  sending a TLS KeyUpdate message. The value of the KEY_PHASE bit is changed
  each time.

At each point, both keying material (see {{key-expansion}}) and the the AEAD
function used by TLS is interchanged with the values that are currently in use
for protecting outbound packets.  Once a change of keys has been made, packets
with higher sequence numbers MUST use the new keying material until a newer set
of keys (and AEAD) are used.

Once a packet protected by a new key has been received, a recipient SHOULD
retain the previous keys for a short period.  Retaining old keys allows the
recipient to decode reordered packets around a change in keys.  Keys SHOULD be
discarded when an endpoints has received all packets with sequence numbers lower
than the lowest sequence number used for the new key, or when it determines that
reordering of those packets is unlikely.

The KEY_PHASE bit does not indicate which keys are in use.  Depending on whether
0-RTT data was sent and accepted, packets protected with keys derived from the
same secret might be marked with different KEY_PHASE values.

Once the TLS handshake is complete, the KEY_PHASE bit allows for the processing
of messages without having to receive the TLS KeyUpdate message that triggers
the key update.  An endpoint MUST NOT initiate more than one key update at a
time.  A new key update cannot be sent until the endpoint has received a
matching KeyUpdate message from its peer; or, if the endpoint did not initiate
the original key update, it has received an acknowledgment of its own KeyUpdate.
This ensures that there are at most two keys to distinguish between at any one
time, for which the KEY_PHASE bit is sufficient.


## Retransmission of TLS Handshake Messages

TLS handshake messages need to be retransmitted with the same level of
cryptographic protection that was originally used to protect them.  A client
would be unable to decrypt retransmissions of a server's handshake messages that
are protected using the application data keys, since the calculation of the
application data keys depend on the contents of the handshake messages.

This restriction means the creation of an exception to the requirement to always
use new keys for sending once they are available.  A server MUST mark the
retransmitted handshake messages with the same KEY_PHASE as the original
messages.

This prevents a server from sending KeyUpdate messages until it has received the
client's Finished message.  Otherwise, packets protected by the updated keys
could be confused for retransmissions of handshake messages.


## QUIC Key Expansion {#key-expansion}

The following table shows QUIC keys, when they are generated and the TLS secret
from which they are derived:

| Key | TLS Secret | Phase |
|:----|:-----------|:------|
| 0-RTT | early_traffic_secret | "QUIC 0-RTT key expansion" |
| 1-RTT | traffic_secret_N | "QUIC 1-RTT key expansion" |

0-RTT keys are those keys that are used in resumed connections prior to the
completion of the TLS handshake.  Data sent using 0-RTT keys might be replayed
and so has some restructions on its use, see {{using-early-data}}.  0-RTT keys
are used after sending or receiving a ClientHello.

1-RTT keys are used after the TLS handshake completes.  There are potentially
multiple sets of 1-RTT keys; new 1-RTT keys are created by sending a TLS
KeyUpdate message.  1-RTT keys are used after sending a Finished or KeyUpdate
message.

The complete key expansion uses the same process for key expansion as defined in
Section 7.3 of [I-D.ietf-tls-tls13].  For example, the Client Write Key for the
data sent immediately after sending the TLS Finished message is:

~~~
   label = "QUIC 1-RTT key expansion, client write key"
   client_write = HKDF-Expand-Label(traffic_secret_0, label,
                                    "", key_length)
~~~

The QUIC record protection initially starts without keying material.  When the
TLS state machine produces the corresponding secret, new keys are generated from
the TLS connection and used to protect the QUIC record protection.

The Authentication Encryption with Associated Data (AEAD) [RFC5116] function
used is the one used by the TLS connection.  For example, if TLS is using the
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, the AEAD_AES_128_GCM function is used.


## QUIC AEAD application

Regular QUIC packets are protected by an AEAD [RFC5116].  Version negotiation
and public reset packets are not protected.

Once TLS has provided a key, the contents of regular QUIC packets immediately
after any TLS messages have been sent are protected by the AEAD selected by TLS.

The key, K, for the AEAD is either the Client Write Key or the Server Write Key,
derived as defined in {{key-expansion}}.

The nonce, N, for the AEAD is formed by combining either the Client Write IV or
Server Write IV with the sequence numbers.  The 48 bits of the reconstructed
QUIC sequence number (see {{seq-num}}) in network byte order is left-padded with
zeros to the N_MAX parameter of the AEAD (see Section 4 of [RFC5116]).  The
exclusive OR of the padded sequence number and the IV forms the AEAD nonce.

The associated data, A, for the AEAD is an empty sequence.

The input plaintext, P, for the AEAD is the contents of the QUIC frame following
the packet number, as described in [I-D.tsvwg-quic-protocol].

The output ciphertext, C, of the AEAD is transmitted in place of P.

Prior to TLS providing keys, no record protection is performed and the
plaintext, P, is transmitted unmodified.

Note:

: QUIC defined a null-encryption that had an additional, hash-based checksum for
  cleartext packets.  This might be added here, but it is more complex.


## Sequence Number Reconstruction {#seq-num}

Each peer maintains a 48-bit sequence number that is incremented with every
packet that is sent, including retransmissions.  The least significant 8-, 16-,
32-, or 48-bits of this number is encoded in the QUIC sequence number field in
every packet.

A receiver maintains the same values, but recovers values based on the packets
it receives.  This is based on the sequence number of packets that it has
received.  A simple scheme predicts the receive sequence number of an incoming
packet by incrementing the sequence number of the most recent packet to be
successfully decrypted by one and expecting the sequence number to be within a
range centered on that value.

A more sophisticated algorithm can almost double the search space by checking
backwards from the most recent sequence for a received (or abandoned) packet.
If a packet was received, then the packet contains a sequence number that is
greater than the most recent sequence number.  If no such packet was found, the
number is assumed to be in the smaller window centered on the next sequence
number, as in the simpler scheme.

Note:

: QUIC has a single, contiguous sequence number space.  In comparison, TLS
  restarts its sequence number each time that record protection keys are
  changed.  The sequence number restart in TLS ensures that a compromise of the
  current traffic keys does not allow an attacker to truncate the data that is
  sent after a key update by sending additional packets under the old key
  (causing new packets to be discarded).

  QUIC does not assume a reliable transport and is therefore required to handle
  attacks where packets are dropped in other ways.

  TLS maintains a separate sequence number that is used for record protection on
  the connection that is hosted on stream 1.  This sequence number is reset
  according to the rules in the TLS protocol.


# Pre-handshake QUIC Messages {#pre-handshake}

Implementations MUST NOT exchange data on any stream other than stream 1 prior
to the completion of the TLS handshake.  However, QUIC requires the use of
several types of frame for managing loss detection and recovery.  In addition,
it might be useful to use the data acquired during the exchange of
unauthenticated messages for congestion management.

This section generally only applies to TLS handshake messages from both peers
and acknowledgments of the packets carrying those messages.  In many cases, the
need for servers to provide acknowledgments is minimal, since the messages that
clients send are small and implicitly acknowledged by the server's responses.

The actions that a peer takes as a result of receiving an unauthenticated packet
needs to be limited.  In particular, state established by these packets cannot
be retained once record protection commences.

There are several approaches possible for dealing with unauthenticated packets
prior to handshake completion:

* discard and ignore them
* use them, but reset any state that is established once the handshake completes
* use them and authenticate them afterwards; failing the handshake if they can't
  be authenticated
* save them and use them when they can be properly authenticated
* treat them as a fatal error

Different strategies are appropriate for different types of data.  This document
proposes that all strategies are possible depending on the type of message.

* Transport parameters and options are made usable and authenticated as part of
  the TLS handshake (see {{quic_parameters}}).
* Most unprotected messages are treated as fatal errors when received except for
  the small number necessary to permit the handshake to complete (see
  {{pre-handshake-unprotected}}).
* Protected packets can either be discarded or saved and later used (see
  {{pre-handshake-protected}}).


## Unprotected Frames Prior to Handshake Completion {#pre-handshake-unprotected}

This section describes the handling of messages that are sent and received prior
to the completion of the TLS handshake.

Sending and receiving unprotected messages is hazardous.  Unless expressly
permitted, receipt of an unprotected message of any kind MUST be treated as a
fatal error.


### STREAM Frames

`STREAM` frames for stream 1 are permitted.  These carry the TLS handshake
messages.

Receiving unprotected `STREAM` frames for other streams MUST be treated as a
fatal error.

Issue:

: Is it possible to send a `STREAM` frame for stream 1 that contains no data?
  Is this detectable?  Does it comprise an attack?  For instance, could an
  attacker inject a frame that appears to contain TLS application data?


### ACK Frames

`ACK` frames are permitted prior to the handshake being complete.  However, an
unauthenticated `ACK` frame can only be used to obtain NACK ranges.  Timestamps
MUST NOT be included in an unprotected ACK frame, since these might be modified
by an attacker with the intent of altering congestion control response.

`ACK` frames MAY be sent a second time once record protection is enabled.  Once
protected, timestamps can be included.

Editor's Note:

: This prohibition might be a little too strong, but this is the only obviously
  safe option.  If the amount of damage that an attacker can do by modifying
  timestamps is limited, then it might be OK to permit the inclusion of
  timestamps.  Note that an attacker need not be on-path to inject an ACK.


### WINDOW_UPDATE Frames

`WINDOW_UPDATE` frames MUST NOT be sent unprotected.

Though data is exchanged on stream 1, the initial flow control window is is
sufficiently large to allow the TLS handshake to complete.  However, this limits
the maximum size of the TLS handshake.  This is unlikely to cause issues unless
a server or client provides an abnormally large certificate chain.

Stream 1 is exempt from the connection-level flow control window.


### Denial of Service with Unprotected Packets ##

Accepting unprotected - specifically unauthenticated - packets presents a denial
of service risk to endpoints.  An attacker that is able to inject unprotected
packets can cause a recipient to drop even protected packets with a matching
sequence number.  The spurious packet shadows the genuine packet, causing the
genuine packet to be ignored as redundant.

Once the TLS handshake is complete, both peers MUST ignore unprotected packets.
The handshake is complete when the server receives a client's Finished message
and when a client receives an acknowledgement that their Finished message was
received.  From that point onward, unprotected messages can be safely dropped.
Note that the client could retransmit its Finished message to the server, so the
server cannot reject such a message.

Since only TLS handshake packets and acknowledgments are sent in the clear, an
attacker is able to force implementations to rely on retransmission for packets
that are lost or shadowed.  Thus, an attacker that intends to deny service to an
endpoint has to drop or shadow protected packets in order to ensure that their
victim continues to accept unprotected packets.  The ability to shadow packets
means that an attacker does not need to be on path.

ISSUE:

: This would not be an issue if QUIC had a randomized starting sequence number.
  If we choose to randomize, we fix this problem and reduce the denial of
  service exposure to on-path attackers.  The only possible problem is in
  authenticating the initial value, so that peers can be sure that they haven't
  missed an initial message.

In addition to denying endpoints messages, an attacker to generate packets that
cause no state change in a recipient.  See {{useless}} for a discussion of these
risks.

To avoid receiving TLS packets that contain no useful data, a TLS implementation
MUST reject empty TLS handshake records and any record that is not permitted by
the TLS state machine.  Any TLS application data or alerts - other than a single
end_of_early_data at the appropriate time - that is received prior to the end of
the handshake MUST be treated as a fatal error.


## Use of 0-RTT Keys {#using-early-data}

If 0-RTT keys are available, the lack of replay protection means that
restrictions on their use are necessary to avoid replay attacks on the protocol.

A client MUST only use 0-RTT keys for the protection of data that is idempotent.
A client MAY wish to apply additional restrictions on what data it sends prior
to the completion of the TLS handshake.  A client otherwise treats 0-RTT keys as
equivalent to 1-RTT keys.

A client that has successfully used 0-RTT keys can send 0-RTT data until it
receives all of the server's handshake messages.  A client SHOULD stop sending
0-RTT data if it receives an indication that 0-RTT data has been rejected.  In
addition to a ServerHello without an early_data extension, an unprotected
handshake message with a KEY_PHASE bit set to 0 indicates that 0-RTT data has
been rejected.

A client SHOULD therefore send its end_of_early_data alert after it has either
received all of the server's handshake messages, or it receives an unprotected
handshake message.  Alternatively phrased, a client is encouraged to use 0-RTT
keys until 1-RTT keys become available.  This prevents stalling of the
connection and allows the client to send continuously.

A server MUST NOT use 0-RTT keys for anything other than TLS handshake messages.
Servers therefore treat packets protected with 0-RTT keys as equivalent to
unprotected packets in determining what can be sent.  A server protects
handshake messages using the 0-RTT key if it decides to accept a 0-RTT key.  A
server MUST still include the early_data extension in its handshake.

This prevents a server from responding to a request using 0-RTT.  This ensures
that all application data from the server enjoy forward secrecy protection.
However, this results in head-of-line blocking at the client because server
responses cannot be decrypted until all the server's handshake messages are
received.


## Protected Frames Prior to Handshake Completion {#pre-handshake-protected}

Due to reordering and loss, protected packets might be received by an endpoint
before the final handshake messages are received.  If these can be decrypted
successfully, such packets MAY be stored and used once the handshake is
complete.

Unless expressly permitted below, encrypted packets MUST NOT be used prior to
completing the TLS handshake, in particular the receipt of a valid Finished
message and any authentication of the peer.  If packets are processed prior to
completion of the handshake, an attacker might use the willingness of an
implementation to use these packets to mount attacks.

TLS handshake messages are covered by record protection during the handshake,
once key agreement has completed.  This means that protected messages need to be
decrypted to determine if they are TLS handshake messages or not.  Similarly,
`ACK` and `WINDOW_UPDATE` frames might be needed to successfully complete the
TLS handshake.

Any timestamps present in `ACK` frames MUST be ignored rather than causing a
fatal error.  Timestamps on protected frames MAY be saved and used once the TLS
handshake completes successfully.

An endpoint MAY save the last protected `WINDOW_UPDATE` frame it receives for
each stream and apply the values once the TLS handshake completes.  Failing
to do this might result in temporary stalling of affected streams.


# QUIC-Specific Additions to the TLS Handshake

QUIC uses the TLS handshake for more than just negotiation of cryptographic
parameters.  The TLS handshake validates protocol version selection, provides
preliminary values for QUIC transport parameters, and allows a server to perform
return routeability checks on clients.


## Protocol and Version Negotiation {#version-negotiation}

The QUIC version negotiation mechanism is used to negotiate the version of QUIC
that is used prior to the completion of the handshake.  However, this packet is
not authenticated, enabling an active attacker to force a version downgrade.

To ensure that a QUIC version downgrade is not forced by an attacker, version
information is copied into the TLS handshake, which provides integrity
protection for the QUIC negotiation.  This does not prevent version downgrade
during the handshake, though it means that such a downgrade causes a handshake
failure.

TBD:

: Determine whether we are using ALPN or a new quic_version extension and
  describe that fully.


## QUIC Extension {#quic_parameters}

QUIC defines an extension for use with TLS.  That extension defines
transport-related parameters.  This provides integrity protection for these
values.  Including these in the TLS handshake also make the values that a client
sets available to a server one-round trip earlier than parameters that are
carried in QUIC frames.  This document does not define that extension.


## Source Address Validation {#source-address}

QUIC implementations describe a source address token.  This is an opaque blob
that a server might provide to clients when they first use a given source
address.  The client returns this token in subsequent messages as a return
routeability check.  That is, the client returns this token to prove that it is
able to receive packets at the source address that it claims.  This prevents the
server from being used in packet reflection attacks.

A source address token is opaque and consumed only by the server.  Therefore it
can be included in the TLS 1.3 pre-shared key identifier for 0-RTT handshakes.
Servers that use 0-RTT are advised to provide new pre-shared key identifiers
after every handshake to avoid linkability of connections by passive observers.
Clients MUST use a new pre-shared key identifier for every connection that they
initiate; if no pre-shared key identifier is available, then resumption is not
possible.

A server that is under load might include a source address token in the cookie
extension of a HelloRetryRequest. (Note: the current version of TLS 1.3 does not
include the ability to include a cookie in HelloRetryRequest.)


# Security Considerations

There are likely to be some real clangers here eventually, but the current set
of issues is well captured in the relevant sections of the main text.

Never assume that because it isn't in the security considerations section it
doesn't affect security.  Most of this document does.


## Packet Reflection Attack Mitigation

A small ClientHello that results in a large block of handshake messages from a
server can be used in packet reflection attacks to amplify the traffic generated
by an attacker.

Certificate caching [I-D.ietf-tls-cached-info] can reduce the size of the
server's handshake messages significantly.

A client SHOULD also pad [RFC7685] its ClientHello to at least 1024 octets (TBD:
tune this value).  A server is less likely to generate a packet reflection
attack if the data it sends is a small multiple of the data it receives.  A
server SHOULD use a HelloRetryRequest if the size of the handshake messages it
sends is likely to exceed the size of the ClientHello.


## Peer Denial of Service {#useless}

QUIC, TLS and HTTP/2 all contain a messages that have legitimate uses in some
contexts, but that can be abused to cause a peer to expend processing resources
without having any observable impact on the state of the connection.  If
processing is disproportionately large in comparison to the observable effects
on bandwidth or state, then this allows a peer to exhaust processing capacity
without consequence.

While there are legitimate uses for some redundant packets, implementations
SHOULD track redundant packets and treat excessive volumes of them as indicative
of an attack.


# IANA Considerations

This document has no IANA actions.  Yet.


--- back

# Acknowledgments

Christian Huitema's knowledge of QUIC is far better than my own.  This would be
even more inaccurate and useless if not for his assistance.  This document has
variously benefited from a long series of discussions with Jana Iyengar, Adam
Langley, Roberto Peon, Eric Rescorla, Ian Swett, and likely many others who are
merely forgotten by a faulty meat computer.
