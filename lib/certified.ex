defmodule Certified do
  @moduledoc """
  The central point for calling into Certified.
  """

  @type server_options() :: [:ssl.tls_server_option()]

  @doc """
  Generates a complete set of options for `:ssl.handshake/2`.

  This uses the Thousand Island `transport_options` config defined in your
  Phoenix `Endpoint`s config, plus updated TLS keys and certs resolved
  using the Acme config in your environment.

  ## Examples

      iex> Certified.generate_transport_options()
      [
        certs_keys: [
          %{certfile: "mycert.pem", keyfile: "mykey.pem"}
        ]
      ]

  """
  @spec generate_transport_options() :: server_options()
  def generate_transport_options() do
    transport_options = Application.get_env(:certified, :transport_options, [])

    case :ets.lookup(:certified_certificate_store, :certs_keys) do
      [] ->
        transport_options

      [{_, certs_keys}] ->
        transport_options
        |> Keyword.put(:certs_keys, certs_keys)
        |> Keyword.reject(fn {key, _val} ->
          key in [:key, :cert, :keyfile, :certfile]
        end)
    end
  end
end
