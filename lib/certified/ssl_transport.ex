defmodule Certified.SSLTransport do
  @behaviour ThousandIsland.Transport
  @moduledoc """
  A thin wrapper around the SSL transport used by Thousand Island.

  This allows Certified to hook into the SSL handshake event, giving us
  the ability to update the SSL certificates used by `:ssl.handshake/2`

  https://hexdocs.pm/thousand_island/ThousandIsland.Transports.SSL.html
  """

  @impl ThousandIsland.Transport
  defdelegate listen(port, user_options), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate accept(listener_socket), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  def handshake(socket) do
    case :ssl.handshake(socket, Certified.generate_transport_options()) do
      {:ok, socket, _protocol_extensions} -> {:ok, socket}
      other -> other
    end
  end

  @impl ThousandIsland.Transport
  defdelegate upgrade(socket, opts), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate controlling_process(socket, pid), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate recv(socket, length, timeout), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate send(socket, data), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate sendfile(socket, filename, offset, length), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate getopts(socket, options), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate setopts(socket, options), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate shutdown(socket, way), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate close(socket), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate sockname(socket), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate peername(socket), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate peercert(socket), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate secure?(), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate getstat(socket), to: ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate negotiated_protocol(socket), to: ThousandIsland.Transports.SSL
end
