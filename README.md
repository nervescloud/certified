# Certified - ACME for the modern Elixir stack

Phoenix + Bandit + ACME, built for distributed deployments.

Certified is built for distributed Phoenix apps that are using Bandit and Thousand Island.
This stack allows Certified to hook into the Erlang `:ssl` `sni_fun` option, which allows for
updated certificates and their keys to be passed through for each request.

This approach allows for multiple certificates and keys to be configured with Certified and then
the corresponding certificate found during connection.

A singular `CertificatesManager` per cluster, orchestrated by `ProcessHub`, is in charge of
loading the certificates from the cache, requesting certificates which aren't already loaded,
and renewing them when they have only 25% of their validity left.

And with the power of `Phoenix.PubSub`, your nodes can sync their certificates without the
need to have shared storage. This also works smoothly when new nodes come online as they
announce their presence and ask for the certificates (and their keys) from
the running `CertificatesManager`.

This integration has been developed for use with [Anchor.dev](https://anchor.dev), which takes care of
ACME challenges for you. LetsEncrypt support has been tested and works smoothly. Sadly ZeroSSL
support hasn't been tested yet due to downtime with their service.

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
included `Certified.sni_fun/0` function, as well as a self-signed key and cert to use on boot.

These settings are added to the `thousand_island_options` of your `Endpoint` config:

```elixir
config :my_app, MyApp.Endpoint,
  url: [host: "myhost.com"],
  https: [
    otp_app: :my_app,
    thousand_island_options: [
      transport_options: [
        sni_fun: &Certified.sni_fun/1,
        keyfile: "priv/cert/selfsigned_key.pem",
        certfile: "priv/cert/selfsigned_cert.pem"
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

## ACME Providers

### LetsEncrypt

```elixir
config :certified,
  domains: System.get_env("ACME_DOMAINS"),
  acme: [
    directory_url: System.get_env("ACME_DIRECTORY_URL"),
    email: System.get_env("ACME_EMAIL")
  ]
```

### ZeroSSL

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

### Anchor.dev (recommended)

```elixir
config :certified,
  domains: System.get_env("ACME_DOMAINS"),
  acme: [
    directory_url: System.get_env("ACME_DIRECTORY_URL"),
    eab: [
      kid: System.get_env("ACME_EAB_KID"),
      hmac_key: System.get_env("ACME_EAB_HMAC_KEY")
    ]
  ],
  challenge_strategy: :automated_dns
```

## Advanced configuration

```elixir
config :certified,
  certificates: [
    %{domains: ["goodtimes.com"]},
    %{domains: ["bestoftimes.com", "the.bestoftimes.com"]}
  ],
  acme: [
    directory_url: System.get_env("CERTIFIED_ACME_DIRECTORY_URL"),
    email: System.get_env("CERTIFIED_ACME_EMAIL"),
    eab: [
      kid: System.get_env("CERTIFIED_ACME_EAB_KID"),
      hmac_key: System.get_env("CERTIFIED_ACME_EAB_HMAC_KEY")
    ]
  ],
  challenge_strategy: :http,
  challenge_strategy_settings: [
    port: 80
  ]
```

### Multiple certificates

```elixir
config :certified,
  certificates: [
    %{domains: ["goodtimes.com"]},
    %{domains: ["bestoftimes.com", "the.bestoftimes.com"]}
  ],
  ...
```

### Dynamic certificates

```elixir
config :certified,
  certificates: &MyApp.Certificates.load_certificate_configs/0,
  ...
```

### Force SSL



### Save certificates to S3

```elixir
config :certified,
  ...
  cache: [
    strategy: Certified.Caches.S3,
    opts: [
      access_key_id: "access_key_id",
      secret_access_key: "secret_access_key",
      bucket: "my-bucket",
      scheme: "https://", # optional, default is "https://"
      host: "a.different.provider.com", # optional, default is taken care of by ExAws,
      region: "auto" # optional, default is "us-east-1"
    ]
  ]
```

### Build your own certificates cache

`Certified.AcmeCache`

```elixir
config :certified,
  ...
  cache: [
    strategy: MyApp.MyCertifiedCache,
    opts: [
      some_config_item: "boop",
      some_other_config_item: "boopboop"
    ]
  ]
```

### HTTP challenge strategy options

```elixir
config :certified,
  ...
  cache: [
    strategy: MyApp.MyCertifiedCache,
    opts: [
      some_config_item: "boop",
      some_other_config_item: "boopboop"
    ]
  ]
```

### Configurable startup process

Disable default startup process and place within your own application's supervision tree.


## Upcoming improvements

- Docs docs docs, and examples
- Add registration timeout
- Support wildcard certs when selecting the right certificate to use
- Support earlier Elixir versions? (switch to Jason or at least allow it to be used)

## Thanks and Attributions

- https://github.com/dominicletz/certmagex
