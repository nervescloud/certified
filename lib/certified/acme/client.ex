defmodule Certified.Acme.Client do
  @moduledoc """
  An ACME client focused on a smooth integration with ACME providers.

  Please note, this has only been tested against Anchor.dev

  More providers coming soon.

  ACME RFC: https://datatracker.ietf.org/doc/html/rfc8555
  JWT verifier: https://jwt.io/
  """

  require Logger

  def supported_provider_operations(directory_url) do
    resp = Req.get!(directory_url, retry: :transient)

    if resp.status != 200, do: raise("Cannot fetch supported provider operations")

    resp.body
  end

  def new_nonce(url) do
    # {_request, response} = request(:get, "#{url}?ts=#{DateTime.utc_now() |> DateTime.to_unix()}")
    {request, response} = request(:head, url)

    if response.status != 200 do
      raise("Cannot get new nonce\nrequest: #{inspect(request)} \nresponse: #{inspect(response)}")
    end

    from_headers(response, "replay-nonce")
  end

  def new_account(url, ec_key, nonce, opts \\ []) do
    protected_section = protected_payload(ec_key, nonce, url)

    payload_section = new_account_payload(opts, url, ec_key)

    signed_body = jwk_sign(ec_key, payload_section, protected_section)

    response =
      request(:post, url, signed_body, error_message: "Cannot generate new account")

    account = %Certified.Acme.Responses.Account{
      account_location: from_headers(response, "location"),
      contact: response.body["contact"],
      status: response.body["status"]
    }

    {account, from_headers(response, "replay-nonce")}
  end

  def new_order(url, domains, account_kid, ec_key, nonce) do
    protected_section = simple_protected_payload(account_kid, url, nonce)

    payload_section = new_order_payload_section(domains)

    signed_body = jwk_sign(ec_key, payload_section, protected_section)

    response = request(:post, url, signed_body, error_message: "Cannot create new order")

    {:ok, expires, _} = DateTime.from_iso8601(response.body["expires"])

    order = %Certified.Acme.Responses.Order{
      order_location: from_headers(response, "location"),
      authorizations: response.body["authorizations"],
      expires: expires,
      finalize_url: response.body["finalize"],
      identifiers: response.body["identifiers"],
      status: response.body["status"],
      certificate_url: response.body["certificate"]
    }

    {order, from_headers(response, "replay-nonce")}
  end

  def new_authorization(url, account_kid, ec_key, nonce) do
    protected_section = simple_protected_payload(account_kid, url, nonce)

    signed_body = jwk_sign(ec_key, "", protected_section)

    response =
      request(:post, url, signed_body,
        error_message: "Cannot create new authorization for #{url}"
      )

    {:ok, expires, _} = DateTime.from_iso8601(response.body["expires"])

    authorization = %Certified.Acme.Responses.Authorization{
      authorization_location: url,
      status: response.body["status"],
      expires: expires,
      identifier: response.body["identifier"],
      challenges: response.body["challenges"]
    }

    {authorization, from_headers(response, "replay-nonce")}
  end

  def request_challenge_validation(url, account_kid, ec_key, nonce) do
    protected_section = simple_protected_payload(account_kid, url, nonce)

    signed_body = jwk_sign(ec_key, JSON.encode!(%{}), protected_section)

    response =
      request(:post, url, signed_body, error_message: "Cannot request challenge for #{url}")

    {response.body, from_headers(response, "replay-nonce")}
  end

  def finalize_order(url, domains, account_kid, ec_key, nonce) do
    {private_key, csr} = generate_csr(domains)

    encoded_csr = X509.CSR.to_der(csr) |> Base.url_encode64(padding: false)

    payload_section = JSON.encode!(%{csr: encoded_csr})

    protected_section = simple_protected_payload(account_kid, url, nonce)

    signed_body = jwk_sign(ec_key, payload_section, protected_section)

    response = request(:post, url, signed_body, error_message: "Cannot finalize order")

    new_nonce = from_headers(response, "replay-nonce")
    retry_after = retry_after(response)

    {:ok, expires, _} = DateTime.from_iso8601(response.body["expires"])

    order = %Certified.Acme.Responses.Order{
      order_location: from_headers(response, "location"),
      authorizations: response.body["authorizations"],
      expires: expires,
      finalize_url: response.body["finalize"],
      identifiers: response.body["identifiers"],
      status: response.body["status"],
      certificate_url: response.body["certificate"]
    }

    {order, private_key, retry_after, new_nonce}
  end

  def get_order(order_url, account_kid, ec_key, nonce) do
    protected_section = simple_protected_payload(account_kid, order_url, nonce)

    signed_body = jwk_sign(ec_key, "", protected_section)

    response =
      request(:post, order_url, signed_body, error_message: "Cannot get order for #{order_url}")

    new_nonce = from_headers(response, "replay-nonce")
    retry_after = retry_after(response)

    {:ok, expires, _} = DateTime.from_iso8601(response.body["expires"])

    order = %Certified.Acme.Responses.Order{
      order_location: order_url,
      authorizations: response.body["authorizations"],
      expires: expires,
      finalize_url: response.body["finalize"],
      identifiers: response.body["identifiers"],
      status: response.body["status"],
      certificate_url: response.body["certificate"]
    }

    {order, retry_after, new_nonce}
  end

  def download_final_certificate(account_kid, certificate_url, ec_key, nonce) do
    protected_section = simple_protected_payload(account_kid, certificate_url, nonce)

    signed_body = jwk_sign(ec_key, "", protected_section)

    response =
      request(:post, certificate_url, signed_body,
        error_message: "Cannot download final certificate"
      )

    {:ok, response.body}
  end

  defp simple_protected_payload(account_location, url, nonce) do
    %{
      nonce: nonce,
      url: url,
      alg: "ES256",
      kid: account_location
    }
    |> JSON.encode!()
  end

  def generate_challenge_signature(token, ec_key) do
    thumbprint =
      signing_key(ec_key)
      |> JOSE.JWK.thumbprint()

    "#{token}.#{thumbprint}"
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

  defp new_account_payload(opts, account_url, ec_key) do
    eab_payload_section = maybe_eab_payload(opts[:eab], account_url, ec_key)

    emails = Enum.map(opts[:emails] || [], fn email -> "mailto:#{email}" end)

    %{
      contact: emails,
      termsOfServiceAgreed: true,
      externalAccountBinding: eab_payload_section
    }
    |> Map.reject(fn {_key, value} -> is_nil(value) end)
    |> JSON.encode!()
  end

  defp maybe_eab_payload(eab, url, ec_key) do
    if eab do
      eab_credentials = eab

      eab_payload(
        eab_credentials.kid,
        eab_credentials.hmac_key,
        url,
        ec_key
      )
    else
      nil
    end
  end

  defp eab_payload(kid, hmac_key, url, ec_key) do
    {:ok, hmac} = Base.url_decode64(hmac_key, padding: false)

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

  defp new_order_payload_section(domains) do
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
  end

  defp jwk_sign(ec_key, payload_section, protected_section) do
    {%{alg: _alg}, body} =
      ec_key
      |> signing_key()
      |> JOSE.JWS.sign(payload_section, protected_section)

    body
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

    {key, csr}
  end

  defp request(:head, url) do
    Req.Request.new(method: :head, url: url, options: [retry: :transient])
    |> Req.Request.put_new_header("user-agent", "elixir-certified-client")
    |> Req.Request.prepend_response_steps(retry: &Req.Steps.retry/1)
    |> Req.Request.prepend_error_steps(retry: &Req.Steps.retry/1)
    |> Req.Request.run_request()
  end

  defp request(:post, url, body, opts) do
    {request, response} =
      Req.Request.new(method: :post, url: url, options: [retry: :transient])
      |> Req.Request.put_new_header("user-agent", "elixir-certified-client")
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
    if value = response.headers[key] do
      hd(value)
    else
      nil
    end
  end

  defp retry_after(response) do
    response
    |> from_headers("retry-after")
    |> parse_retry_after()
  end

  defp parse_retry_after(nil), do: nil

  defp parse_retry_after(retry_after) do
    case Integer.parse(retry_after) do
      {seconds, _} -> seconds
      _ -> 3
    end
  end
end
