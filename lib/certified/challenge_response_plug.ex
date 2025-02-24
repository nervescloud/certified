defmodule Certified.ChallengeResponsePlug do
  @moduledoc """
  This plug handles ACME HTTP challenges, as well as capturing all other
  requests and redirecting to the HTTPS endpoint.

  The SSL redirection options can be configured using the `:challenge_opts`
  key in the `:certified` configuration, including the port Bandit listens on.

  Below is an example configuration, including the defaults:

    config :certified,
      ...
      challenge: :http,
      challenge_opts: [
        port: 80,
        force_ssl: [rewrite_on: [:x_forwarded_proto], host: nil]
      ]

  You `challenge` option is not required. If you want to disable to plug, including
  the SSL redirection, you can set the `:challenge` option to `:none`, `nil`, or `false`.
  """
  @behaviour Plug

  require Logger

  @default_ssl_opts [rewrite_on: [:x_forwarded_proto], host: nil]

  @impl Plug
  def init(_) do
    ssl_opts = Keyword.get(challenge_opts(), :force_ssl)

    if ssl_opts do
      Plug.SSL.init(ssl_opts)
    else
      nil
    end
  end

  @impl Plug
  def call(%{request_path: "/.well-known/acme-challenge/" <> token} = conn, _) do
    case challenge_response(token) do
      nil ->
        Logger.debug(
          "[Certified.ChallengeResponsePlug] Authorization not found for token #{token}"
        )

        conn
        |> Plug.Conn.send_resp(404, "Challenge not found")
        |> Plug.Conn.halt()

      response ->
        Logger.debug(
          "[Certified.ChallengeResponsePlug] Authorization signature sent for token #{token}"
        )

        conn
        |> Plug.Conn.send_resp(200, response)
        |> Plug.Conn.halt()
    end
  end

  @impl Plug
  def call(conn, state) do
    if state do
      Plug.SSL.call(conn, state)
    else
      Logger.debug("[Certified.ChallengeResponsePlug] Ignoring request for #{conn.request_path}")

      conn
      |> Plug.Conn.send_resp(404, "Not Found")
      |> Plug.Conn.halt()
    end
  end

  defp challenge_response(token) do
    Logger.debug("[Certified.ChallengeResponsePlug] Requesting signature for token #{token}")

    broadcast("challenge/request", %{token: token, reply_to: self()})

    receive do
      %{event: "challenge/request", payload: %{signature: signature}} ->
        signature
    after
      1_000 ->
        nil
    end
  end

  defp broadcast(event, payload) do
    :ok =
      Phoenix.PubSub.broadcast(
        Certified.PubSub,
        "certified:certificate_registration:#{payload[:token]}",
        %{
          event: event,
          payload: payload
        }
      )
  end

  defp challenge_opts() do
    Application.get_env(:certified, :challenge_opts, force_ssl: @default_ssl_opts)
  end
end
