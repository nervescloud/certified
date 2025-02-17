# Certified - ACME for the modern Elixir stack

Phoenix + Bandit + ACME, built for distributed deployments.

Certified is built for distributed Phoenix apps that are using Bandit and Thousand Island.
This stack allows Certified to hook into the `:ssl.handshake` function call and inject updated
certificates and their private keys. This approach also supports multiple certificates
and keys to be passed along.

A singular `CertificateUpdater` per cluster, orchestrated by `ProcessHub`, is in charge of
requesting the certificates (if they aren't available on another node), and renewing them
when they have only 25% of their validity left.

And with the power of `Phoenix.PubSub`, your nodes can sync their certificates without the
need to have shared storage. This also works smoothly when new nodes come online as they
announce their presence and ask for the certificates and keys from the running `CertificateUpdater`.

**Important**

This integration has been developed for use with Anchor.dev, which takes care of
ACME challenges for you. Future releases will support other ACME providers and support HTTP
challenges.


## Installation

```elixir
def deps do
  [
    {:certified, "~> 0.1.0"}
  ]
end
```

## Configure

In your config, usually `config/runtime.exs`, change your `Endpoint` to use the
included `Certified.SSLTransport` transport, as well as a self-signed key and cert to use on boot.

These settings are added to the `thousand_island_options` of your `Endpoint` config:

```elixir
config :my_app, MyApp.Endpoint,
  url: [host: "myhost.com"],
  https: [
    port: 4040,
    otp_app: :my_app,
    thousand_island_options: [
      # How we hook into the `:ssl.handshake` flow
      transport_module: Certified.SSLTransport,
      transport_options: [
        # Some self signed certs to use on application startup
        certs_keys: [%{certfile: "cert.pem", keyfile: "key.pem"}]
      ]
    ]
  ]
```

And then all you need to do is to configure Certified with your ACME details.

```elixir
config :certified,
  domains: System.get_env("ACME_DOMAINS"),
  acme: [
    directory_url: System.get_env("ACME_DIRECTORY_URL"),
    eab: [
      kid: System.get_env("ACME_EAB_KID"),
      hmac_key: System.get_env("ACME_EAB_HMAC_KEY")
    ]
  ]
```

## Upcoming improvements

- Docs docs docs, and examples
- Storage adapters for the EC key and certs (File system and S3)
- HTTP challenges (https://github.com/mtrudel/bandit?tab=readme-ov-file#using-bandit-with-plug-applications)
- Don't require EAB tokens
- Full testing against LetsEncrypt and ZeroSSL
- Support earlier Elixir versions? (switch to Jason or at least allow it to be used)
