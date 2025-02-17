defmodule Certified.CertificateUpdateListener do
  use GenServer

  alias Phoenix.PubSub
  alias Phoenix.Socket.Broadcast

  defmodule State do
    defstruct certificate_store: nil,
              configured?: false

    @type t ::
            %__MODULE__{
              certificate_store: reference(),
              configured?: boolean()
            }
  end

  def start_link(_) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl GenServer
  def init(_) do
    table = :ets.new(:certified_certificate_store, [:set, :protected, :named_table])

    :ok = PubSub.subscribe(Certified.PubSub, "certified:certificate_update_listener")

    # Give a few extra seconds before announcing the node is online so
    # we can make sure (be defensive) that the node has joined the cluster
    Process.send_after(self(), :announce_online, :timer.seconds(5))

    {:ok, %State{certificate_store: table}}
  end

  @impl GenServer
  def handle_info(%Broadcast{event: "certs_keys/updated", payload: certs_keys}, state) do
    true = :ets.insert(state.certificate_store, {:certs_keys, certs_keys})

    {:noreply, %State{state | configured?: true}}
  end

  @impl GenServer
  def handle_info(%Broadcast{event: "sync/request"}, state) do
    case :ets.lookup(state.certificate_store, :certs_keys) do
      [] ->
        true

      [{_, certs_keys}] ->
        broadcast("sync/response", certs_keys)
    end

    {:noreply, state}
  end

  @impl GenServer
  def handle_info(:announce_online, state) do
    broadcast("listener/online")

    {:noreply, state}
  end

  defp broadcast(event, payload \\ %{}) do
    Phoenix.Channel.Server.broadcast_from!(
      Certified.PubSub,
      self(),
      "certified:certificate_updater",
      event,
      payload
    )
  end
end
