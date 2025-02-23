defmodule Certified.CertificatesManager do
  use GenServer

  alias Certified.AcmeCache
  alias Certified.Certificate.Registration

  alias Phoenix.PubSub

  require Logger

  # Check certificate expiration every 50 minutes
  @renewal_interval :timer.minutes(50)

  # Renew certs which have only a quarter of their lifetime left
  @renew_threshold 0.75

  defmodule State do
    defstruct acme: nil,
              certificates: nil,
              ec_key: nil,
              certificate_cache: nil,
              renewal_timer: nil,
              configured?: false

    @type t ::
            %__MODULE__{
              acme: map(),
              certificates: [map()],
              ec_key: :public_key.ecdsa_public_key(),
              certificate_cache: reference(),
              renewal_timer: reference(),
              configured?: boolean()
            }
  end

  def start_link(_) do
    GenServer.start_link(__MODULE__, nil, name: __MODULE__)
  end

  @impl GenServer
  def init(_) do
    certified_env = Application.get_all_env(:certified)

    table = :ets.new(:certified_certificate_updater_cache, [:set, :protected, :named_table])

    {:ok, timer_ref} = :timer.send_interval(@renewal_interval, :renewal_check)

    :ok = PubSub.subscribe(Certified.PubSub, "certified:certificates_manager")

    state = %State{
      certificates: resolve_certificates_config(certified_env),
      ec_key: resolve_ec_key(certified_env),
      acme: Map.new(certified_env[:acme]),
      certificate_cache: table,
      renewal_timer: timer_ref
    }

    {:ok, state, {:continue, :load_from_sources}}
  end

  @doc """
  Before registering new certificates:
  - try to load from the configured `CacheStrategy`
  - ask other nodes if they have certificates loaded and ready to share
  - if no one has certificates, request new ones from the provider
  """
  @impl GenServer
  def handle_continue(:load_from_sources, state) do
    case AcmeCache.load_certificates!() do
      nil ->
        Logger.debug(
          "[Certified.CertificatesManager] No certificates available from #{AcmeCache.friendly_cache_name()} cache"
        )

        send(self(), :start_registration)

        {:noreply, state}

      certs_keys ->
        Logger.debug(
          "[Certified.CertificatesManager] #{Enum.count(certs_keys)} certificate pair(s) loaded from #{AcmeCache.friendly_cache_name()} cache"
        )

        if cached_matches_config?(certs_keys, state.certificates) do
          certs_keys
          |> filtered_cached(state.certificates)
          |> update_ets_and_broadcast(state.certificate_cache)
        else
          Logger.debug(
            "[Certified.CertificatesManager] Cached certificates do not match configuration, requesting new certificates from provider"
          )
        end

        # renew or register new certificates
        send(self(), :start_registration)

        {:noreply, %State{state | configured?: true}}
    end
  end

  @impl GenServer
  def handle_info(%{event: "listener/online"}, state) do
    case cached_certificates() do
      [] ->
        :ok

      certs_keys ->
        broadcast("certs_keys/updated", certs_keys)
    end

    {:noreply, state}
  end

  @impl GenServer
  def handle_info(
        %{event: "registration/completed", payload: %{status: :invalid} = payload},
        state
      ) do
    {updated_certificate, updated_certificates} =
      update_certificate_status(payload, state.certificates)

    Logger.debug(
      "[Certified.CertificatesManager] Certificate registration failed : #{inspect(updated_certificate)}"
    )

    {:noreply, %State{state | certificates: updated_certificates}}
  end

  @impl GenServer
  def handle_info(%{event: "registration/status", payload: %{status: :issued} = payload}, state) do
    {updated_certificate, updated_certificates} =
      update_certificate_status(payload, state.certificates)

    Logger.debug(
      "[Certified.CertificatesManager] Certificate registration completed successfully : #{inspect(updated_certificate)}"
    )

    update_ets_and_broadcast(payload, state.certificate_cache)

    AcmeCache.save_certificates!([payload])

    {:noreply, %State{state | certificates: updated_certificates}}
  end

  @impl GenServer
  def handle_info(%{event: "registration/status", payload: payload}, state) do
    {updated_certificate, updated_certificates} =
      update_certificate_status(payload, state.certificates)

    Logger.debug(
      "[Certified.CertificatesManager] Certificate registration status update: #{inspect(updated_certificate)}"
    )

    {:noreply, %State{state | certificates: updated_certificates}}
  end

  @impl GenServer
  def handle_info(:start_registration, state) do
    cond do
      cached_certificates() == [] ->
        Logger.debug("[Certified.CertificatesManager] Requesting certificates")
        request_certificates(state)

      should_renew?() ->
        Logger.debug("[Certified.CertificatesManager] Renewing certificates")
        request_certificates(state)

      true ->
        Logger.debug("[Certified.CertificatesManager] No certificates need renewing")
    end

    {:noreply, %State{state | configured?: true}}
  end

  defp update_ets_and_broadcast(payloads, ets_table) when is_list(payloads) do
    Logger.debug(
      "[Certified.CertificatesManager] Broadcasting #{Enum.count(payloads)} certificate(s) to all nodes"
    )

    Enum.each(payloads, fn payload ->
      domains =
        payload.id
        |> Base.url_decode64!(padding: false)
        |> String.split(":")

      cert_key = %{
        domains: domains,
        key_pem: payload.private_key_pem,
        cert_pem: payload.certificate_pem
      }

      true = :ets.insert(ets_table, {payload.id, cert_key})
    end)

    pem_certs_keys =
      :ets.match(ets_table, {:_, :"$2"})
      |> List.flatten()

    certs_keys =
      Enum.map(pem_certs_keys, fn %{domains: domains, key_pem: key_pem, cert_pem: cert_pem} ->
        key =
          key_pem
          |> X509.from_pem()
          |> List.first()
          |> X509.PrivateKey.to_der()

        cert =
          cert_pem
          |> X509.from_pem()
          |> Enum.map(&X509.Certificate.to_der/1)

        %{key: {:ECPrivateKey, key}, cert: cert, domains: domains}
      end)

    broadcast("certs_keys/updated", certs_keys)
  end

  defp update_ets_and_broadcast(payload, ets_table) do
    update_ets_and_broadcast([payload], ets_table)
  end

  defp request_certificates(state) do
    state.certificates
    |> Enum.filter(fn certificate_config ->
      certificate_config.status == :pending
    end)
    |> Enum.each(fn certificate_config ->
      request_certificate(certificate_config, state)
    end)
  end

  defp request_certificate(certificate_config, state) do
    challenge_strategy =
      state.acme
      |> Map.get(:challenge_strategy, "http")
      |> String.to_atom()

    eab = if state.acme[:eab], do: Map.new(state.acme[:eab]), else: nil

    emails =
      [state.acme[:email] || state.acme[:emails]]
      |> Enum.reject(fn email -> is_nil(email) end)
      |> List.flatten()

    acme_opts = [
      eab: eab,
      challenge_strategy: challenge_strategy,
      emails: emails
    ]

    child_spec =
      [state.acme.directory_url, state.ec_key, acme_opts, certificate_config]
      |> Registration.child_spec()

    case ProcessHub.start_child(:certified, child_spec) do
      {:ok, _pid} ->
        Logger.debug(
          "[Certified.CertificatesManager] Certificate registration flow started: #{inspect(certificate_config)}"
        )

        :ok

      {:error, {:already_started, _pid}} ->
        Logger.debug(
          "[Certified.CertificatesManager] Certificate registration flow running: #{inspect(certificate_config)}"
        )

        :ok

      {:error, reason} ->
        Logger.error(
          "[Certified.CertificatesManager] Failed to start certificate registration flow: #{inspect(reason)} (#{inspect(certificate_config)}"
        )

        {:error, reason}
    end
  end

  defp cached_matches_config?(certs_keys, certificates_config) do
    Enum.all?(certificates_config, fn certificate_config ->
      Enum.any?(certs_keys, fn cert_key ->
        cert_key.id == certificate_config.id
      end)
    end)
  end

  defp filtered_cached(certs_keys, certificates_config) do
    filtered =
      Enum.filter(certs_keys, fn cert_key ->
        Enum.any?(certificates_config, fn certificate_config ->
          certificate_config.id == cert_key.id
        end)
      end)

    diff = Enum.count(certs_keys) - Enum.count(filtered)

    if diff > 0 do
      Logger.warning(
        "[Certified.CertificatesManager] #{diff} certificates have been removed from the cached list as they can't be found in the configuration"
      )
    end

    filtered
  end

  defp update_certificate_status(payload, certificates) do
    updated_certificate =
      certificates
      |> Enum.find(fn certificate ->
        certificate.id == payload.id
      end)
      |> Map.put(:status, payload.status)

    updated_certificates =
      certificates
      |> Enum.reject(fn certificate ->
        certificate.id == updated_certificate.id
      end)
      |> Enum.concat([updated_certificate])

    {updated_certificate, updated_certificates}
  end

  defp resolve_certificates_config(env) do
    cond do
      env[:certificates] ->
        env[:certificates]

      env[:domain] ->
        [%{domains: [env[:domain]]}]

      env[:domains] && is_binary(env[:domains]) ->
        [%{domains: String.split(env[:domains], ",")}]

      env[:domains] && is_list(env[:domains]) ->
        [%{domains: env[:domains]}]

      true ->
        raise("[Certified.CertificatesManager] No certificates or domain configured")
    end
    |> Enum.map(fn certificate ->
      normalized_domains = List.flatten([certificate.domains])

      id =
        normalized_domains
        |> Enum.join(":")
        |> Base.url_encode64(padding: false)

      %{id: id, domains: normalized_domains, status: :pending}
    end)
  end

  def resolve_ec_key(env) do
    case env[:ec_key] do
      nil ->
        if key = AcmeCache.load_ec_key!() do
          key
        else
          new_ec_key()
          |> tap(fn ec ->
            AcmeCache.save_ec_key!(ec)
          end)
        end

      key ->
        key
        |> Base.url_decode64!(padding: false)
        |> X509.PrivateKey.from_pem!()
    end
  end

  defp should_renew?() do
    case cached_certificates() do
      [] ->
        false

      certs_keys ->
        Enum.any?(certs_keys, fn %{cert_pem: cert_pem} ->
          should_renew_cert?(cert_pem)
        end)
    end
  end

  defp cached_certificates() do
    :ets.match(:certified_certificate_updater_cache, {:_, :"$2"})
    |> List.flatten()
  end

  defp should_renew_cert?(cert_pem) do
    {:Validity, from, until} =
      cert_pem
      |> X509.from_pem()
      |> List.first()
      |> X509.Certificate.validity()

    from_dt = X509.DateTime.to_datetime(from)
    until_dt = X509.DateTime.to_datetime(until)

    validity_length = DateTime.diff(until_dt, from_dt, :day)

    current_period = DateTime.diff(DateTime.utc_now(), from_dt, :day)

    # renew if we are past the threshold of the current validity period,
    round(validity_length * @renew_threshold) < current_period
  end

  defp broadcast(event, payload) do
    Phoenix.PubSub.broadcast_from!(
      Certified.PubSub,
      self(),
      "certified:node_listener",
      %{event: event, payload: payload}
    )
  end

  defp new_ec_key() do
    :public_key.generate_key({:namedCurve, :secp256r1})
  end
end
