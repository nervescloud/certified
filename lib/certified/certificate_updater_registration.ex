defmodule Certified.CertificateUpdaterRegistration do
  use GenServer, restart: :transient

  require Logger

  alias Certified.CertificateUpdater

  @default_registration_delay_seconds 10

  def start_link(_) do
    GenServer.start_link(__MODULE__, nil, name: __MODULE__)
  end

  @impl GenServer
  def init(_) do
    # Give a little time for the node to join the cluster
    Process.send_after(
      self(),
      :register_certificate_updater,
      :timer.seconds(@default_registration_delay_seconds)
    )

    {:ok, nil}
  end

  @impl GenServer
  def handle_info(:register_certificate_updater, _) do
    ProcessHub.start_child(:certified_certificate_updater, %{
      id: :certificate_updater,
      start: {CertificateUpdater, :start_link, []}
    })
    |> case do
      {:ok, _} ->
        Logger.debug(
          "[Certified.CertificateUpdaterRegistration] CertificateUpdater started successfully"
        )

        {:stop, :normal, nil}

      {:error, {:already_started, _}} ->
        Logger.debug(
          "[Certified.CertificateUpdaterRegistration] CertificateUpdater already started and managed by ProcessHub"
        )

        {:stop, :normal, nil}

      error ->
        Logger.error(
          "[Certified.CertificateUpdaterRegistration] CertificateUpdater registration encountered an error: #{inspect(error)}"
        )

        {:stop, {error}, nil}
    end
  end
end
