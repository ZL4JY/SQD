**SQD FAQ V1.1**

**Purpose:** SQD is intended to facilitate research and understanding of a protocol implemented in the more than 20 year-old, and now end-of-life, Quantar platform.

**Intellectual property:** As far as the author is aware there is no publicly available documentation on the Quantar V.24 protocol. Yes, the protocol is proprietary but reverse-engineering a protocol is legitimate, particularly in order to achieve interoperability.  Hardly legal advice but refer:
https://en.wikipedia.org/wiki/Reverse_engineering

**Restrictions:** This implementation as further detailed below is based on the Quantar TR/TR mode. At present SQD does not dissect Quantar to DIU or Quantar to comparator operation, but future extensions are possible.

Current list of Frame Types dissected (named (mostly) according to the TIA Project 25, Fixed Station Interface Messages and Procedures, standard TIA-102.BAHA):
```
Start
Voice Header Part 1
Voice Header Part 2
IMBE Voice 1
IMBE Voice 2
IMBE Voice 3 + Link Control
IMBE Voice 4 + Link Control
IMBE Voice 5 + Link Control
IMBE Voice 6 + Link Control
IMBE Voice 7 + Link Control
IMBE Voice 8 + Link Control
IMBE Voice 9 + Low Speed Data
IMBE Voice 10
IMBE Voice 11
IMBE Voice 12 + Encryption Sync
IMBE Voice 13 + Encryption Sync
IMBE Voice 14 + Encryption Sync
IMBE Voice 15 + Encryption Sync
IMBE Voice 16 + Encryption Sync
IMBE Voice 17 + Encryption Sync
IMBE Voice 18 + Low Speed Data
Page call frame
```
Page call frame now handles emergency calls and shows TGID.  Do not use this for real emergency decoding as this is based on empirical and unverified testing.

Current list of parameters dissected:
```
Value: RSSI
Value: inverse signal
Value: function byte
Value: TGID
Value: Called RID
Value: RID 
Value: LDU1 low speed data
Value: LDU2 low speed data
Value: ALGID
Value: KeyID
Value: Page target RID
Value: MFID
Flag: RT/RT mode in Start and Voice Header Part 1
Flag: Link Control Format - $00= Voice 4 flag contains TGID, $03=Voice 4 contains Call target RID
Flag: Encrypted/legacy encryption/no encryption/
```
