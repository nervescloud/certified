defmodule Certified.Supervisor do
  use Supervisor

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    children =
      if Application.get_env(:certified, :acme) do
        [
          {Phoenix.PubSub, name: Certified.PubSub},
          Certified.CertificateUpdateListener,
          Certified.CertificateUpdaterRegistration,
          ProcessHub.child_spec(%ProcessHub{hub_id: :certified_certificate_updater})
        ]
      else
        []
      end

    Supervisor.init(children, strategy: :one_for_one)
  end
end
