defmodule Certified.Supervisor do
  @moduledoc false
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
          Certified.NodeListener,
          ProcessHub.child_spec(%ProcessHub{hub_id: :certified}),
          Certified.CertificatesManagerRegistration
        ] ++ http_challenge_supervisor()
      else
        []
      end

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp http_challenge_supervisor() do
    opts = Application.get_all_env(:certified)

    if Keyword.get(opts, :challenge_strategy, :http) == :http do
      settings = Keyword.get(opts, :challenge_strategy_settings, port: 80)
      [{Bandit, plug: Certified.ChallengeResponsePlug, port: settings[:port]}]
    else
      []
    end
  end
end
