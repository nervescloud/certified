defmodule Certified.CertificatesManager.DelayedRegistration do
  @moduledoc false
  use GenServer, restart: :transient

  require Logger

  alias Certified.CertificatesManager

  @default_registration_delay_seconds 5

  def start_link(_) do
    GenServer.start_link(__MODULE__, nil, name: __MODULE__)
  end

  @impl GenServer
  def init(_) do
    # Give a little time for the node to join the cluster
    Process.send_after(
      self(),
      :register_certificates_manager,
      :timer.seconds(@default_registration_delay_seconds)
    )

    {:ok, nil}
  end

  @impl GenServer
  def handle_info(:register_certificates_manager, _) do
    ProcessHub.start_child(:certified, %{
      id: :certificates_manager,
      start: {CertificatesManager, :start_link, [nil]}
    })
    |> case do
      {:ok, _} ->
        Logger.debug(
          "[Certified.CertificatesManager.DelayedRegistration] CertificatesManager started successfully"
        )

        {:stop, :normal, nil}

      {:error, {:already_started, _}} ->
        Logger.debug(
          "[Certified.CertificatesManager.DelayedRegistration] CertificatesManager already started and managed by ProcessHub"
        )

        {:stop, :normal, nil}

      error ->
        Logger.error(
          "[Certified.CertificatesManager.DelayedRegistration] CertificatesManager registration encountered an error: #{inspect(error)}"
        )

        {:stop, {error}, nil}
    end
  end
end
