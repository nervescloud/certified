if Code.loaded?(ExAws.S3) do
  defmodule Certified.Caches.S3 do
    @behaviour Certified.AcmeCache
    @moduledoc """
    A S3 cache implementing the `AcmeCache` behaviour.
    """

    @prefix "certificates"

    @impl Certified.AcmeCache
    def save_certificates!(certs_keys) do
      Enum.each(certs_keys, fn %{cert: cert, key: {:ECPrivateKey, key}} ->
        full_cert = X509.Certificate.from_der!(cert)
        private_key = X509.PrivateKey.from_der!(key)

        [common_name] = X509.Certificate.subject(full_cert, "CN")

        bucket()
        |> ExAws.S3.put_object(
          "#{@prefix}/#{common_name}/cert.pem",
          X509.Certificate.to_pem(full_cert)
        )
        |> ExAws.request!(s3_config())

        bucket()
        |> ExAws.S3.put_object(
          "#{@prefix}/#{common_name}/key.pem",
          X509.PrivateKey.to_pem(private_key)
        )
        |> ExAws.request!(s3_config())
      end)
    end

    @impl Certified.AcmeCache
    def load_certificates!() do
      bucket_contents()
      |> Enum.group_by(fn file ->
        file.key
        |> String.trim("#{@prefix}/")
        |> String.split("/")
        |> List.first()
      end)
      |> Enum.map(fn {common_name, files} ->
        cert_file =
          Enum.find(files, fn file ->
            file.key =~ ~r{^#{@prefix}/#{common_name}/cert.pem$}
          end)

        key_file =
          Enum.find(files, fn file ->
            file.key =~ ~r{^#{@prefix}/#{common_name}/key.pem$}
          end)

        cert =
          bucket()
          |> ExAws.S3.get_object(cert_file.key)
          |> ExAws.request!(s3_config())
          |> then(fn result -> result.body end)
          |> X509.Certificate.from_pem!()
          |> X509.Certificate.to_der()

        private_key =
          bucket()
          |> ExAws.S3.get_object(key_file.key)
          |> ExAws.request!(s3_config())
          |> then(fn result -> result.body end)
          |> X509.PrivateKey.from_pem!()
          |> X509.PrivateKey.to_der()

        %{cert: cert, key: {:ECPrivateKey, private_key}}
      end)
      |> case do
        [] -> nil
        certs_keys -> certs_keys
      end
    end

    @impl Certified.AcmeCache
    def save_ec_key!(ec_key) do
      bucket()
      |> ExAws.S3.put_object(
        "ec_key.pem",
        X509.PrivateKey.to_pem(ec_key)
      )
      |> ExAws.request!(s3_config())

      :ok
    end

    @impl Certified.AcmeCache
    def load_ec_key!() do
      bucket()
      |> ExAws.S3.get_object("ec_key.pem")
      |> ExAws.request!(s3_config())
      |> then(fn result -> result.body end)
      |> case do
        "" -> nil
        content -> X509.PrivateKey.from_pem!(content)
      end
    end

    defp bucket_contents() do
      bucket()
      |> ExAws.S3.list_objects(prefix: @prefix)
      |> ExAws.request!(s3_config())
      |> then(fn result -> result.body.contents end)
    end

    defp s3_config() do
      opts = Application.get_env(:certified, :cache)[:opts]

      vars = [
        access_key_id: opts[:access_key_id],
        secret_access_key: opts[:secret_access_key],
        scheme: opts[:scheme],
        host: opts[:host],
        region: opts[:region]
      ]

      ExAws.Config.new(:s3, vars)
      |> Map.to_list()
    end

    defp bucket() do
      Application.get_env(:certified, :cache)[:opts][:bucket]
    end
  end
else
  defmodule Certified.Caches.S3 do
    @behaviour Certified.AcmeCache
    @moduledoc """
    A S3 cache implementing the `AcmeCache` behaviour.
    """

    @impl Certified.AcmeCache
    def save_certificates!(_certs_keys) do
      raise "S3 cache not available. Please add `:ex_aws` and `:ex_aws_s3` to your dependencies."
    end

    @impl Certified.AcmeCache
    def load_certificates!() do
      raise "S3 cache not available. Please add `:ex_aws` and `:ex_aws_s3` to your dependencies."
    end

    @impl Certified.AcmeCache
    def save_ec_key!(_ec_key) do
      raise "S3 cache not available. Please add `:ex_aws` and `:ex_aws_s3` to your dependencies."
    end

    @impl Certified.AcmeCache
    def load_ec_key!() do
      raise "S3 cache not available. Please add `:ex_aws` and `:ex_aws_s3` to your dependencies."
    end
  end
end
