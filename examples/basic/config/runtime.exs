import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/basic start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :basic, BasicWeb.Endpoint, server: true
end

if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :basic, Basic.Repo,
    # ssl: true,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    socket_options: maybe_ipv6

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"
  ssl_port = String.to_integer(System.get_env("PORT") || "443")

  config :basic, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :basic, BasicWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    https: [
      port: ssl_port,
      cipher_suite: :strong,
      thousand_island_options: [
        transport_options: [
          sni_fun: &Certified.sni_fun/1,
          keyfile: "priv/cert/selfsigned_key.pem",
          certfile: "priv/cert/selfsigned.pem"
        ]
      ]
    ],
    secret_key_base: secret_key_base
end

if domains = System.get_env("CERTIFIED_ACME_DOMAINS") do
  config :certified,
    domains: domains,
    acme: [
      directory_url: System.get_env("CERTIFIED_ACME_DIRECTORY_URL"),
      email: System.get_env("CERTIFIED_ACME_EMAIL")
    ]
end
