# Purpose-rendering fixtures

`purpose-shipped.pem` and `purpose-added.pem` are synthetic, self-signed
P-256 CA certificates generated for the renderer's unit tests. No private
keys are stored. Both are valid from 2020-01-01 to 2120-01-01 and have the
same subject, `CN=trustd synthetic purpose test CA`, so they also exercise
hashed-directory collisions. Their serial numbers are 1 and 2 respectively.

The added certificate has a CodeSigning extended-key-usage extension.
The tests check that the original DER survives rendering unchanged; they
do not ask a TLS consumer to validate it. Registry purpose metadata and
certificate extensions are separate inputs, and consumer acceptance is
outside these tests.

Generated with Python cryptography's CertificateBuilder, ephemeral in-memory
EC keys, critical BasicConstraints(ca=True, path_length=None), and SHA-256
signatures. These are test data only; never install them as trust anchors.
