defmodule Certified.AcmeCache do
  @moduledoc """
  A cache adapter behaviour for saving and loading Certificates and Private Keys,
  as well as the public key used for signing JWKs.
  """

  @type cert_key_pair() :: %{{:ECPrivateKey, binary()}, cert: binary()}

  @doc """
  Save Certificates and Private Keys to the cache.
  """
  @callback save_certificates!([cert_key_pair()]) :: :ok | {:error, reason :: atom()}

  @doc """
  Loads all Certificates and Private Keys from the cache.
  """
  @callback load_certificates!() :: [cert_key_pair()] | nil

  @doc """
  Cache the EC Key used for signing JWKs.
  """
  @callback save_ec_key!(:public_key.ecdsa_private_key()) :: :ok | {:error, reason :: atom()}

  @doc """
  Loads the EC Key from the cache.
  """
  @callback load_ec_key!() :: :public_key.ecdsa_public_key() | nil

  def load_certificates!() do
    cache().load_certificates!()
  end

  def save_certificates!(certs_keys) do
    cache().save_certificates!(certs_keys)
  end

  def load_ec_key!() do
    cache().load_ec_key!()
  end

  def save_ec_key!(ec_key) do
    cache().save_ec_key!(ec_key)
  end

  def friendly_cache_name() do
    cache()
    |> to_string()
    |> String.split(".")
    |> List.last()
  end

  defp cache() do
    Application.get_env(:certified, :cache, strategy: Certified.Caches.LocalFileSystem)
    |> Keyword.get(:strategy)
  end
end
