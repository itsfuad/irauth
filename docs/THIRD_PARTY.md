# Third-party components

IRAuth v0.1 integrates rather than vendors these projects:

- **Howdy** (`boltgolt/howdy`) — face-recognition backend. GPL-3.0 upstream;
  installed separately by the operating system/user. IRAuth communicates
  through PAM/CLI boundaries and does not copy Howdy source.
- **howdy-as-passkey** (`NicklasKleemann/howdy-as-passkey`) — MIT virtual FIDO2
  bridge, fetched at a pinned commit by `irauthctl passkey install`. Its own
  license remains authoritative for the fetched source/binary.

The pin exists to make installation reproducible and auditable; upgrades should
be explicit commits in this repository after review.
