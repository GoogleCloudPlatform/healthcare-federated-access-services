# `healthcare-federated-access-services`

This repository contains an implementation of the
[GA4GH](https://www.ga4gh.org/) Researcher Identity and
Authentication Profile specifications.

**IMPORTANT: This is an early pre-release that should only be used for testing and demo purposes. Only synthetic or public datasets should be used. Customer support is not currently provided.**

## Contributing

See the [contributing](CONTRIBUTING.md) document for information about how to
contribute to this repository.

## Notice

This is not an officially supported Google product.

## How to Deploy

See [deploy.md](./deploy.md)

## Configuration

Please check `deploy/config/ic-template` and `deploy/config/dam-template` for a configuration example.
For more details, please check `IcConfig` in `proto/ic/v1/ic_service.proto` and `DamConfig` in `proto/dam/v1/dam_service.proto`.
