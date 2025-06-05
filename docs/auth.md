# Authentication

The provisioning system uses mTLS to authenticate endpoints and to encrypt all
data exchanged between clients and servers.

In addition, a token based authentication layer is implemented
to authenticate client requests at the call level. The provisioning
system manages credentials mapping allowed service calls to SKU/client
credentials. Such credentials will be provided by [ATE](https://github.com/lowRISC/opentitan-provisioning/wiki/ate.md) clients.

## References

* [gRPC Authentication Guide](https://grpc.io/docs/guides/auth/). The system is
  currently configured to use SSL/TLS with client side authentication. This is
  sometimes referred to as
  [mTLS](https://en.wikipedia.org/wiki/Mutual_authentication#mTLS).
  `CompositeChannelCredentials` are used to integrate
  [*Call Credentials* ](https://grpc.io/docs/guides/auth/#credential-types)
  with *Channel Credentials*.

## Developer Notes

### Endpoint Certificates

The following command generates keys and certificates for all endpoints. The
`SubjectAltName` is set to `localhost`. All clients should connect using this
address. See the [script](https://github.com/lowRISC/opentitan-provisioning/blob/main/config/certs/gen_certs.sh) implementation for
more details.

```console
config/certs/gen_certs.sh
```
**Note**: At the moment, all client and services share the same root
certificate. Calling the `gen_certs.sh` script requires restarting all the
servers and clients.

## Read More

* [Documentation index](https://github.com/lowRISC/opentitan-provisioning/wiki/Home)
