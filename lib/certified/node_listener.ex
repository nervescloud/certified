defmodule Certified.NodeListener do
  use GenServer

  alias Phoenix.PubSub

  @announce_online_delay :timer.seconds(3)

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

    :ok = PubSub.subscribe(Certified.PubSub, "certified:node_listener")

    # Give a few extra seconds before announcing the node is online so
    # we can make sure (be defensive) that the node has joined the cluster
    Process.send_after(self(), :announce_online, @announce_online_delay)

    {:ok, %State{certificate_store: table}}
  end

  @impl GenServer
  def handle_info(%{event: "certs_keys/updated", payload: certs_keys}, state) do
    true = :ets.insert(state.certificate_store, {:certs_keys, certs_keys})

    {:noreply, %State{state | configured?: true}}
  end

  @impl GenServer
  def handle_info(:announce_online, state) do
    Phoenix.PubSub.broadcast_from!(
      Certified.PubSub,
      self(),
      "certified:certificates_manager",
      %{event: "listener/online"}
    )

    {:noreply, state}
  end
end
