defmodule Certified do
  @moduledoc """
  The central point for calling into Certified.
  """

  @type cert() :: :public_key.der_encoded() | [:public_key.der_encoded()]
  @type cert_and_key() :: [cert: cert(), key: :ssl.key()]

  @doc """
  Finds the first matching certificate and key for the given domain, or
  returns `:undefined` if no match is found.

  This function is used by the Erlang `:ssl` application, via Cowboy or Bandit.

  ## Examples

      iex> Certified.sni_fun("example.com")
      [cert: "mycert.pem", key: "mykey.pem"]

      iex> Certified.sni_fun("other-example.com")
      :undefined

  """
  @spec sni_fun(String.t()) :: cert_and_key() | :undefined
  def sni_fun(domain) do
    :ets.match(:certified_certificate_store, {:_, :"$2"})
    |> List.flatten()
    |> Enum.find(fn %{domains: domains} -> to_string(domain) in domains end)
    |> case do
      nil -> :undefined
      %{key: key, cert: cert} -> [key: key, cert: cert]
    end
  end
end
