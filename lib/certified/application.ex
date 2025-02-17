defmodule Certified.Application do
  @moduledoc false
  use Application

  require Logger

  def start(_type, _args) do
    if Application.get_env(:certified, :start_on_boot, true) do
      Logger.debug("[Certified.Application] starting supervisor tree")
      Certified.Supervisor.start_link(nil)
    else
      Logger.debug("[Certified.Application] `start_on_boot` has been disabled, noop")
      Supervisor.start_link([], strategy: :one_for_one)
    end
  end
end
