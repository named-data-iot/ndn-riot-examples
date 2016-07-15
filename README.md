Example applications for NDN-RIOT
=================================

## Getting started

To build applications, create environment using the following commands:

    mkdir riot
    cd riot
    git clone https://github.com/named-data-iot/RIOT
    git clone https://github.com/named-data-iot/ndn-riot
    git clone https://github.com/named-data-iot/ndn-riot-examples

Afterwards, to build one of the available applications:

    cd ndn-riot-examples/<APP>
    make <FLAGS_REQUIRED>

## Compatibility

The examples were known to work with the following versions of RIOT-OS and NDN-RIOT module,
but may work with later (latest) versions:

- **RIOT-OS**: 49d460c9237f6efacc9d3f31784080ed0941e692
- **NDN-RIOT**: 6fc40252f815ea66ff0c379e8ad82c28313026f0
