defmodule Certified.Acme.Client do
  @moduledoc """
  An ACME client focused on a smooth integration with ACME providers.

  Please note, this has only been tested against Anchor.dev

  More providers coming soon.

  ACME RFC: https://datatracker.ietf.org/doc/html/rfc8555
  JWT verifier: https://jwt.io/
  """

  require Logger

  def generate_certificate(domains, acme_url, ec_key, opts \\ []) do
    domains = List.flatten([domains])
    Logger.debug("[Acme] Generating certificate(s) for [#{Enum.join(domains, ", ")}]")

    Logger.debug("[Acme] Fetching the supported provider operations")
    ops = supported_provider_operations(acme_url)

    Logger.debug("[Acme] Requesting a fresh nonce")
    nonce = new_nonce(ops["newNonce"])

    Logger.debug("[Acme] Generating a new account")
    {account_location, nonce} = new_account(ops["newAccount"], ec_key, nonce, opts)

    Logger.debug("[Acme] Creating a new order")
    {finalize_url, nonce} = new_order(domains, account_location, ops["newOrder"], ec_key, nonce)

    Logger.debug("[Acme] Finalizing the order")

    [
      certificate_private_key_pem,
      final_order_url,
      new_nonce
    ] = finalize_order(domains, account_location, finalize_url, ec_key, nonce)

    Logger.debug("[Acme] Downloading the final certificate")

    {:ok, final_certificate_pem} =
      download_final_certificate(account_location, final_order_url, ec_key, new_nonce)

    Logger.debug("[Acme] Certificate downloaded successfully")
    {certificate_private_key_pem, final_certificate_pem}
  end

  def supported_provider_operations(acme_uri) do
    resp = Req.get!(acme_uri, retry: :transient)

    if resp.status != 200, do: raise("Cannot fetch supported provider operations")

    resp.body
  end

  def new_nonce(url) do
    # {_request, response} = request(:get, "#{url}?ts=#{DateTime.utc_now() |> DateTime.to_unix()}")
    {_request, response} = request(:get, url)

    if response.status != 200, do: raise("Cannot get new nonce")

    from_headers(response, "replay-nonce")
  end

  def new_account(url, ec_key, nonce, opts \\ []) do
    protected_section = protected_payload(ec_key, nonce, url)

    eab_credentials = opts[:eab]

    eab_payload_section =
      eab_payload(
        eab_credentials.kid,
        eab_credentials.hmac_key,
        url,
        ec_key
      )

    emails =
      [opts[:email] || opts[:emails]]
      |> Enum.reject(fn email -> is_nil(email) end)
      |> List.flatten()
      |> Enum.map(fn email -> "mailto:#{email}" end)

    payload_section =
      %{
        contact: emails,
        termsOfServiceAgreed: true,
        externalAccountBinding: eab_payload_section
      }
      |> JSON.encode!()

    {%{alg: _alg}, body} =
      ec_key
      |> signing_key()
      |> JOSE.JWS.sign(payload_section, protected_section)

    response = request(:post, url, body, error_message: "Cannot generate new account")

    new_nonce = from_headers(response, "replay-nonce")
    account_location = from_headers(response, "location")

    {account_location, new_nonce}
  end

  def new_order(domains, account_location, provider_url, ec_key, nonce) do
    protected_section =
      %{
        nonce: nonce,
        url: provider_url,
        alg: "ES256",
        kid: account_location
      }
      |> JSON.encode!()

    payload_section =
      %{
        identifiers:
          Enum.map(domains, fn domain ->
            %{
              type: "dns",
              value: domain
            }
          end)
      }
      |> JSON.encode!()

    {%{alg: _alg}, body} =
      ec_key
      |> signing_key()
      |> JOSE.JWS.sign(payload_section, protected_section)

    response = request(:post, provider_url, body, error_message: "Cannot create new order")

    new_nonce = from_headers(response, "replay-nonce")

    {response.body["finalize"], new_nonce}
  end

  def finalize_order(domain, account_location, finalize_url, ec_key, nonce) do
    {private_key, csr} = generate_csr(domain)

    payload_section = JSON.encode!(%{csr: csr})

    protected_section =
      %{
        nonce: nonce,
        url: finalize_url,
        alg: "ES256",
        kid: account_location
      }
      |> JSON.encode!()

    {%{alg: _alg}, body} =
      ec_key
      |> signing_key()
      |> JOSE.JWS.sign(payload_section, protected_section)

    response = request(:post, finalize_url, body, error_message: "Cannot finalize order")

    new_nonce = from_headers(response, "replay-nonce")

    [
      private_key,
      response.body["certificate"],
      new_nonce
    ]
  end

  def download_final_certificate(account_location, certificate_url, ec_key, nonce) do
    protected_section =
      %{
        nonce: nonce,
        url: certificate_url,
        alg: "ES256",
        kid: account_location
      }
      |> JSON.encode!()

    payload_section = ""

    {%{alg: _alg}, body} =
      ec_key
      |> signing_key()
      |> JOSE.JWS.sign(payload_section, protected_section)

    response =
      request(:post, certificate_url, body, error_message: "Cannot download final certificate")

    {:ok, response.body}
  end

  defp protected_payload(ec_key, nonce, url) do
    %{
      alg: "ES256",
      jwk: public_key_map(ec_key),
      nonce: nonce,
      url: url
    }
    |> JSON.encode!()
  end

  defp eab_payload(kid, hmac_key, url, ec_key) do
    {:ok, hmac} = Base.url_decode64(hmac_key)

    protected_section =
      %{url: url, kid: kid, alg: "HS256"}
      |> JSON.encode!()
      |> Base.url_encode64(padding: false)

    payload_section =
      public_key_map(ec_key)
      |> JSON.encode!()
      |> Base.url_encode64(padding: false)

    signature =
      :crypto.mac(:hmac, :sha256, hmac, "#{protected_section}.#{payload_section}")
      |> Base.url_encode64(padding: false)

    %{
      protected: protected_section,
      payload: payload_section,
      signature: signature
    }
  end

  defp public_key_map(ec_key) do
    {%{kty: :jose_jwk_kty_ec}, public_key} =
      ec_key
      |> JOSE.JWK.from_key()
      |> JOSE.JWK.to_public()
      |> JOSE.JWK.to_map()

    public_key
  end

  defp signing_key(ec_key) do
    {_, account_key} =
      ec_key
      |> JOSE.JWK.from_key()
      |> JOSE.JWK.to_map()

    account_key
  end

  defp generate_csr(domains) do
    key = X509.PrivateKey.new_ec(:secp256r1)

    csr =
      X509.CSR.new(key, "CN=#{List.first(domains)}",
        extension_request: [
          X509.Certificate.Extension.subject_alt_name(domains)
        ]
      )
      |> X509.CSR.to_der()
      |> Base.url_encode64(padding: false)

    {X509.PrivateKey.to_pem(key), csr}
  end

  defp request(:get, url) do
    Req.Request.new(method: :get, url: url, options: [retry: :transient])
    |> Req.Request.put_new_header("user-agent", "elixir-acme-client")
    |> Req.Request.prepend_response_steps(retry: &Req.Steps.retry/1)
    |> Req.Request.prepend_error_steps(retry: &Req.Steps.retry/1)
    |> Req.Request.run_request()
  end

  defp request(:post, url, body, opts) do
    {request, response} =
      Req.Request.new(method: :post, url: url, options: [retry: :transient])
      |> Req.Request.put_new_header("user-agent", "elixir-acme-client")
      |> Req.Request.put_new_header("content-type", "application/jose+json")
      |> Req.Request.put_new_header("accept", "application/json")
      |> then(fn request -> %{request | body: JSON.encode!(body)} end)
      # |> Req.Request.prepend_response_steps(retry: &Req.Steps.retry/1)
      |> Req.Request.append_response_steps(
        decompress_body: &Req.Steps.decompress_body/1,
        decode_body: &decode_body/1
      )
      # |> Req.Request.prepend_error_steps(retry: &Req.Steps.retry/1)
      |> Req.Request.run_request()

    if response.status not in [200, 201] do
      error_message = opts[:error_message] || "Error completing request"
      raise("#{error_message}\nrequest: #{inspect(request)} \nresponse: #{inspect(response)}")
    end

    response
  end

  defp decode_body({request, response}) do
    format =
      response
      |> Req.Response.get_header("content-type")
      |> hd()
      |> MIME.extensions()

    if format == ["json"] do
      {request, put_in(response.body, JSON.decode!(response.body))}
    else
      {request, response}
    end
  end

  defp from_headers(response, key) do
    hd(response.headers[key])
  end
end
