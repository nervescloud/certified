import Config

# Configure your database
config :basic, Basic.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "basic_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

# For development, we disable any cache and enable
# debugging and code reloading.
#
# The watchers configuration can be used to run external
# watchers to your application. For example, we can use it
# to bundle .js and .css sources.
# Binding to loopback ipv4 address prevents access from other machines.
config :basic, BasicWeb.Endpoint,
  # Change to `ip: {0, 0, 0, 0}` to allow access from other machines.
  https: [
    port: System.get_env("PORT", "443") |> String.to_integer(),
    cipher_suite: :strong,
    otp_app: :basic,
    thousand_island_options: [
      transport_options: [
        sni_fun: &Certified.sni_fun/1,
        keyfile: "priv/cert/selfsigned_key.pem",
        certfile: "priv/cert/selfsigned.pem"
      ]
    ]
  ],
  check_origin: false,
  code_reloader: true,
  debug_errors: true,
  secret_key_base: "v8Bq9A/4O7Wpd8wlMrDpN4wUvFFSxD6gACcUrAC5d+dzc+QoeDKN6UaagbfJhQ4c",
  watchers: [
    esbuild: {Esbuild, :install_and_run, [:basic, ~w(--sourcemap=inline --watch)]},
    tailwind: {Tailwind, :install_and_run, [:basic, ~w(--watch)]}
  ]

# ## SSL Support
#
# In order to use HTTPS in development, a self-signed
# certificate can be generated by running the following
# Mix task:
#
#     mix phx.gen.cert
#
# Run `mix help phx.gen.cert` for more information.
#
# The `http:` config above can be replaced with:
#
#     https: [
#       port: 4001,
#       cipher_suite: :strong,
#       keyfile: "priv/cert/selfsigned_key.pem",
#       certfile: "priv/cert/selfsigned.pem"
#     ],
#
# If desired, both `http:` and `https:` keys can be
# configured to run both http and https servers on
# different ports.

# Watch static and templates for browser reloading.
config :basic, BasicWeb.Endpoint,
  live_reload: [
    patterns: [
      ~r"priv/static/(?!uploads/).*(js|css|png|jpeg|jpg|gif|svg)$",
      ~r"priv/gettext/.*(po)$",
      ~r"lib/basic_web/(controllers|live|components)/.*(ex|heex)$"
    ]
  ]

# Enable dev routes for dashboard and mailbox
config :basic, dev_routes: true

# Do not include metadata nor timestamps in development logs
config :logger, :console, format: "[$level] $message\n"

# Set a higher stacktrace during development. Avoid configuring such
# in production as building large stacktraces may be expensive.
config :phoenix, :stacktrace_depth, 20

# Initialize plugs at runtime for faster development compilation
config :phoenix, :plug_init_mode, :runtime

config :phoenix_live_view,
  # Include HEEx debug annotations as HTML comments in rendered markup
  debug_heex_annotations: true,
  # Enable helpful, but potentially expensive runtime checks
  enable_expensive_runtime_checks: true

# Disable swoosh api client as it is only required for production adapters.
config :swoosh, :api_client, false
