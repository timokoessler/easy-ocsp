# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2024-08

### Added

-   Export `downloadIssuerCert` function

### Changed

-   The function `getCertURLs` is no longer async
-   Update dependencies

## [1.1.0] - 2024-05

### Added

-   Add `getRawOCSPResponse` function to get only the bytes of the OCSP response
-   New option `rawResponse` to get the raw OCSP response additionally to the parsed response

### Changed

-   Update dependencies

## [1.0.1] - 2024-01

### Changed

-   Fix CommonJS import
-   Update dependencies

## [1.0.0] - 2024-01

### Added

-   Automatically convert url to domain in `getCertStatusByDomain`
-   Add examples

### Changed

-   Throw error if the certificate is already expired
-   Update dependencies

## [0.3.0] - 2023-12

### Added

-   Return the revocation reason when the certificate is revoked, if available
-   Check licenses of dependencies

### Changed

-   Add VSCode recommended extensions
-   Fix failing tests because of expired certificate
-   Update dependencies

## [0.2.0] - 2023-10

### Added

-   Publish package via GitHub Actions

### Changed

-   Fixed downloading issuer cert when the data is pem encoded

## [0.1.0] - 2023-09

_This is the initial release._
