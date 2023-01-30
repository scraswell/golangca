# Certificate database
## index.txt
The index.txt file is an ascii file consisting of 6 (not 4) tab-separated
fields. Some of those fields may be empty and might appear not to exist at
all.

The 6 fields are:

0) Entry type. May be "V" (valid), "R" (revoked) or "E" (expired).
Note that an expired may have the type "V" because the type has
not been updated. 'openssl ca -updatedb' does such an update.
1) Expiration datetime.
2) Revokation datetime. This is set for any entry of the type "R".
3) Serial number.
4) File name of the certificate. This doesn't seem to be used,
ever, so it's always "unknown".
5) Certificate subject name.