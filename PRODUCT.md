# SecureDrive

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Confirmed: a security project demo audience, with cryptography prominent.

## Product Purpose

Demonstrate secure file storage and make the encryption, integrity checks, signatures, and performance inspectable.

## Capabilities and Constraints

Existing Flask/Jinja application. Register and log in; upload, download, share with registered users, and delete owned files. Inspect plaintext and ciphertext, SHA-256 hashes, Ed25519 signatures, avalanche results, and timings. Run the text Crypto Lab with optional tampering. View the audit chain and performance graphs.

The user explicitly requires no functionality changes. Preserve routes, request methods, field names, CSRF tokens, validation, access control, encryption, persistence, and all existing result data. UI changes belong in templates and static assets. No fabricated security certifications, live verification claims, or end-to-end encryption claims.

## Brand Commitments

Keep the SecureDrive name. The interface should convey secure storage and support a polished cryptography demonstration.

Confirmed visual preference: light workspace, white surfaces, blue actions, and a familiar dashboard.

## Evidence on Hand

app.py, crypto_utils.py, lab_core.py, and the existing templates establish capabilities and output. Actual data supplies all counts, file information, audit statuses, and measurements.

## Product Principles

- Preserve working behavior.
- Make the cryptographic evidence easy to examine.
- Distinguish implemented mechanisms from verified outcomes.
- Keep routine file operations easy to find.
