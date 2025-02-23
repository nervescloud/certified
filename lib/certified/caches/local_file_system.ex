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

    Enum.each(certs_keys, fn payload ->
      cert_cache_path = Path.join(certificates_path(), payload.id)
      File.mkdir_p!(cert_cache_path)

      Path.join(cert_cache_path, "cert.pem")
      |> File.write!(payload.certificate_pem)

      Path.join(cert_cache_path, "key.pem")
      |> File.write!(payload.private_key_pem)
    end)

    :ok
  end

  @impl Certified.AcmeCache
  def load_certificates!() do
    if File.dir?(certificates_path()) do
      File.ls!(certificates_path())
      |> Enum.filter(fn path -> File.dir?(Path.join(certificates_path(), path)) end)
      |> Enum.map(fn certificate_id ->
        cert_key_path = Path.join(certificates_path(), certificate_id)

        cert_path = Path.join(cert_key_path, "cert.pem")
        key_path = Path.join(cert_key_path, "key.pem")

        if File.exists?(cert_path) && File.exists?(key_path) do
          %{
            id: certificate_id,
            certificate_pem: File.read!(cert_path),
            private_key_pem: File.read!(key_path)
          }
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
