# SigV4 test cases

Sixteen cases from AWS's Signature Version 4 test suite, copied unchanged from
[awslabs/aws-c-auth](https://github.com/awslabs/aws-c-auth) at commit
`f556deacd6e6d9dbf540ff00a9bf383688076874`, `tests/aws-signing-test-suite/v4/<case>/`:
`context.json`, `request.txt`, `header-canonical-request.txt`, `header-string-to-sign.txt` and
`header-signed-request.txt`. Licensed under the Apache License 2.0 (`LICENSE`, and `NOTICE`
where present).

`src/sigv4/tests.rs` signs each request with its context and checks the canonical request,
the string to sign and the `Authorization` header. The cases cover what Helios signs:
query strings, header handling, session tokens and bodies. Path normalization cases are left out,
because the signer only takes canonical paths.
