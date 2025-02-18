defmodule Certified.Caches.LocalFileSystem do
  @behaviour Certified.AcmeCache
  @moduledoc """
  A local file system cache implementing the `AcmeCache` behaviour.
  """

  @default_certified_path "tmp/.certified"
  @certificates_path "certificates"

  @impl Certified.AcmeCache
  def save_certificates!(certs_keys) do
    File.mkdir_p!(certificates_path())

    Enum.each(certs_keys, fn %{cert: cert, key: {:ECPrivateKey, key}} ->
      full_cert = X509.Certificate.from_der!(cert)
      [common_name] = X509.Certificate.subject(full_cert, "CN")

      private_key_pem = X509.PrivateKey.from_der!(key)

      cert_cache_path = Path.join(certificates_path(), common_name)
      File.mkdir_p!(cert_cache_path)

      Path.join(cert_cache_path, "cert.pem")
      |> File.write!(X509.Certificate.to_pem(full_cert))

      Path.join(cert_cache_path, "key.pem")
      |> File.write!(X509.PrivateKey.to_pem(private_key_pem))
    end)

    :ok
  end

  @impl Certified.AcmeCache
  def load_certificates!() do
    if File.dir?(certificates_path()) do
      File.ls!(certificates_path())
      |> Enum.filter(fn path -> File.dir?(Path.join(certificates_path(), path)) end)
      |> Enum.map(fn domain ->
        domain_path = Path.join(certificates_path(), domain)

        cert_path = Path.join(domain_path, "cert.pem")
        key_path = Path.join(domain_path, "key.pem")

        if File.exists?(cert_path) && File.exists?(key_path) do
          cert =
            File.read!(cert_path)
            |> X509.Certificate.from_pem!()
            |> X509.Certificate.to_der()

          key =
            File.read!(key_path)
            |> X509.PrivateKey.from_pem!()
            |> X509.PrivateKey.to_der()

          %{cert: cert, key: {:ECPrivateKey, key}}
        end
      end)
    else
      nil
    end
  end

  @impl Certified.AcmeCache
  def save_ec_key!(ec_key) do
    File.mkdir_p!(certified_path())

    Path.join(certified_path(), "ec_key.pem")
    |> File.write!(X509.PrivateKey.to_pem(ec_key))

    :ok
  end

  @impl Certified.AcmeCache
  def load_ec_key!() do
    if File.dir?(certified_path()) do
      ec_key_path = Path.join(certified_path(), "ec_key.pem")

      if File.exists?(ec_key_path) do
        File.read!(ec_key_path)
        |> X509.PrivateKey.from_pem!()
      end
    else
      nil
    end
  end

  defp certified_path() do
    Path.expand(@default_certified_path)
  end

  defp certificates_path() do
    Path.join([certified_path(), @certificates_path])
  end
end
