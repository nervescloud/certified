defmodule Certified.CertificateUpdater do
  use GenServer

  alias Certified.Acme.Client

  alias Phoenix.PubSub
  alias Phoenix.Socket.Broadcast

  @renewal_interval :timer.minutes(50)

  defmodule State do
    defstruct acme: nil,
              domains: nil,
              certificate_cache: nil,
              renewal_timer: nil,
              configured?: false

    @type t ::
            %__MODULE__{
              acme: map(),
              domains: [String.t()],
              certificate_cache: reference(),
              renewal_timer: reference(),
              configured?: boolean()
            }
  end

  def start_link() do
    GenServer.start_link(__MODULE__, nil, name: __MODULE__)
  end

  @impl GenServer
  def init(_) do
    certified_env = Application.get_all_env(:certified)

    table = :ets.new(:certified_certificate_updater_cache, [:set, :protected, :named_table])

    {:ok, timer_ref} = :timer.send_interval(@renewal_interval, :renewal_check)

    :ok = PubSub.subscribe(Certified.PubSub, "certified:certificate_updater")

    # ask all the listeners out there if they have certs to share
    broadcast("sync/request")

    # in case no one is there to answer, or no one has certs to share
    Process.send_after(self(), :renewal_check, :timer.seconds(5))

    state = %State{
      domains: resolve_domain_config(certified_env),
      acme: Map.new(certified_env[:acme]),
      certificate_cache: table,
      renewal_timer: timer_ref
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_info(%Broadcast{event: "sync/response", payload: certs_keys}, state) do
    true = :ets.insert(state.certificate_cache, {:certs_keys, certs_keys})

    {:noreply, %State{state | configured?: true}}
  end

  @impl GenServer
  def handle_info(%Broadcast{event: "listener/online"}, state) do
    case :ets.lookup(:certified_certificate_updater_cache, :certs_keys) do
      [] ->
        true

      [{_, certs_keys}] ->
        broadcast("certs_keys/updated", certs_keys)
    end

    {:noreply, state}
  end

  @impl GenServer
  def handle_info(:renewal_check, state) do
    if should_renew?() do
      request_certificates(state)
    end

    {:noreply, %State{state | configured?: true}}
  end

  defp request_certificates(state) do
    {private_key_pem, certificate_pem} =
      Client.generate_certificate(state.domains, state.acme.directory_url,
        eab: Map.new(state.acme.eab)
      )

    private_key =
      private_key_pem
      |> X509.PrivateKey.from_pem!()
      |> X509.PrivateKey.to_der()

    certificate =
      certificate_pem
      |> X509.Certificate.from_pem!()
      |> X509.Certificate.to_der()

    certs_keys = [%{cert: certificate, key: {:ECPrivateKey, private_key}}]

    true = :ets.insert(state.certificate_cache, {:certs_keys, certs_keys})

    broadcast("certs_keys/updated", certs_keys)

    :ok
  end

  defp resolve_domain_config(env) do
    cond do
      env[:domain] ->
        env[:domain]

      env[:domains] && is_binary(env[:domains]) ->
        String.split(env[:domains], ",")

      env[:domains] && is_list(env[:domains]) ->
        env[:domains]

      true ->
        raise("[Certified.CertificateUpdater] No domain configured")
    end
  end

  defp should_renew?() do
    case :ets.lookup(:certified_certificate_updater_cache, :certs_keys) do
      [] ->
        true

      [{_, certs_keys}] ->
        Enum.any?(certs_keys, fn %{cert: certificate} ->
          should_renew_cert?(certificate)
        end)
    end
  end

  defp should_renew_cert?(certificate) do
    {:Validity, from, until} =
      certificate
      |> X509.Certificate.from_der!()
      |> X509.Certificate.validity()

    from_dt = X509.DateTime.to_datetime(from)
    until_dt = X509.DateTime.to_datetime(until)

    validity_length = DateTime.diff(until_dt, from_dt, :day)

    current_period = DateTime.diff(DateTime.utc_now(), from_dt, :day)

    # if we are 75% the way through the current validity period,
    # then it's time to renew
    round(validity_length * 0.75) < current_period
  end

  defp broadcast(event, payload \\ %{}) do
    Phoenix.Channel.Server.broadcast_from!(
      Certified.PubSub,
      self(),
      "certified:certificate_update_listener",
      event,
      payload
    )
  end
end
