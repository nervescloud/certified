defmodule Certified.Certificate.Registration do
  use GenServer

  require Logger

  alias Certified.Acme.Client

  @default_retry_after_seconds 3

  defmodule State do
    defstruct provider_urls: nil,
              certificate_config: nil,
              acme_opts: nil,
              account_key: nil,
              account: nil,
              order: nil,
              authorizations: nil,
              private_key: nil

    @type t ::
            %__MODULE__{
              provider_urls: map(),
              certificate_config: map(),
              acme_opts: Keyword.t(),
              account_key: :public_key.ecdsa_private_key(),
              account: Certified.Acme.Responses.Account.t() | nil,
              order: Certified.Acme.Responses.Order.t() | nil,
              authorizations: [Certified.Acme.Responses.Authorization.t()] | nil,
              private_key: :public_key.ecdsa_private_key() | nil
            }
  end

  def child_spec([_, _, _, certificate_config] = args) do
    %{
      id: String.to_atom("registration_#{certificate_config.id}"),
      start: {__MODULE__, :start_link, [args]},
      restart: :transient
    }
  end

  def start_link(args) do
    GenServer.start_link(__MODULE__, args)
  end

  @impl GenServer
  def init([directory_url, ec_key, acme_opts, certificate_config]) do
    provider_urls = Client.supported_provider_operations(directory_url)

    state = %State{
      provider_urls: provider_urls,
      certificate_config: Map.delete(certificate_config, :status),
      acme_opts: acme_opts,
      account_key: ec_key
    }

    send(self(), :registration_flow)

    {:ok, state}
  end

  @impl GenServer
  def handle_info(:registration_flow, state) do
    send(self(), {:registration_flow, nil})

    {:noreply, state}
  end

  @impl GenServer
  def handle_info({:registration_flow, nil}, state) do
    nonce = Client.new_nonce(state.provider_urls["newNonce"])

    send(self(), {:registration_flow, nonce})

    {:noreply, state}
  end

  # Create account
  @impl GenServer
  def handle_info({:registration_flow, nonce}, state) when is_nil(state.account) do
    log(state.certificate_config.domains, "Creating account")

    {account, nonce} =
      Client.new_account(
        state.provider_urls["newAccount"],
        state.account_key,
        nonce,
        state.acme_opts
      )

    send(self(), {:registration_flow, nonce})

    {:noreply, %State{state | account: account}}
  end

  # Create order
  @impl GenServer
  def handle_info({:registration_flow, nonce}, state) when is_nil(state.order) do
    log(state.certificate_config.domains, "Creating order")

    {order, nonce} =
      Client.new_order(
        state.provider_urls["newOrder"],
        state.certificate_config.domains,
        state.account.account_location,
        state.account_key,
        nonce
      )

    broadcast(%{
      id: state.certificate_config.id,
      status: :order_created
    })

    send(self(), {:registration_flow, nonce})

    {:noreply, %State{state | order: order}}
  end

  # Create authorizations
  @impl GenServer
  def handle_info({:registration_flow, nonce}, state)
      when state.order.status == "pending" and is_nil(state.authorizations) do
    log(state.certificate_config.domains, "Starting the validation process")

    {authorizations, new_nonce} =
      Enum.map_reduce(state.order.authorizations, nonce, fn authorization_url, nonce ->
        {authorization, nonce_after_authorization} =
          Client.new_authorization(
            authorization_url,
            state.account.account_location,
            state.account_key,
            nonce
          )

        if Enum.any?(authorization.challenges) do
          http_challenge =
            authorization.challenges
            |> Enum.find(fn challenge -> challenge["type"] == "http-01" end)

          :ok =
            Phoenix.PubSub.subscribe(
              Certified.PubSub,
              "certified:certificate_registration:#{http_challenge["token"]}"
            )

          {_challenge, nonce_after_challenge} =
            Client.request_challenge_validation(
              http_challenge["url"],
              state.account.account_location,
              state.account_key,
              nonce_after_authorization
            )

          {authorization, nonce_after_challenge}
        else
          {authorization, nonce_after_authorization}
        end
      end)

    broadcast(%{
      id: state.certificate_config.id,
      status: :validations_requested
    })

    send(self(), {:registration_flow, new_nonce})

    {:noreply, %State{state | authorizations: authorizations}}
  end

  # Finalize order
  @impl GenServer
  def handle_info({:registration_flow, nonce}, state)
      when state.order.status == "ready" and is_nil(state.private_key) do
    log(state.certificate_config.domains, "Finalizing order")

    {order, private_key, retry_after, nonce} =
      Client.finalize_order(
        state.order.finalize_url,
        state.certificate_config.domains,
        state.account.account_location,
        state.account_key,
        nonce
      )

    broadcast(%{
      id: state.certificate_config.id,
      status: :finalizing
    })

    interval = :timer.seconds(retry_after || @default_retry_after_seconds)

    Process.send_after(self(), {:registration_flow, nonce}, interval)

    {:noreply, %State{state | order: order, private_key: private_key}}
  end

  # Download certificate
  @impl GenServer
  def handle_info({:registration_flow, nonce}, state) when state.order.status == "valid" do
    log(state.certificate_config.domains, "Downloading the certificate")

    {:ok, certificate} =
      Client.download_final_certificate(
        state.account.account_location,
        state.order.certificate_url,
        state.account_key,
        nonce
      )

    private_key_pem = X509.PrivateKey.to_pem(state.private_key)

    broadcast(%{
      id: state.certificate_config.id,
      status: :issued,
      private_key_pem: private_key_pem,
      certificate_pem: certificate
    })

    {:stop, :normal, nil}
  end

  # Download certificate
  @impl GenServer
  def handle_info({:registration_flow, _nonce}, state) when state.order.status == "invalid" do
    log(state.certificate_config.domains, "Order completed with status: invalid")

    broadcast(%{
      id: state.certificate_config.id,
      status: :invalid
    })

    {:stop, :normal, nil}
  end

  # Check order status
  @impl GenServer
  def handle_info({:registration_flow, nonce}, state)
      when state.order.status in ["pending", "ready", "processing"] do
    log(state.certificate_config.domains, "Checking order status")

    {order, retry_after, nonce} =
      Client.get_order(
        state.order.order_location,
        state.account.account_location,
        state.account_key,
        nonce
      )

    log(state.certificate_config.domains, "Order status: #{order.status}")

    if order.status in ["pending", "ready", "processing"] do
      Process.send_after(
        self(),
        {:registration_flow, nonce},
        :timer.seconds(retry_after || @default_retry_after_seconds)
      )
    else
      send(self(), {:registration_flow, nonce})
    end

    {:noreply, %State{state | order: order}}
  end

  @impl GenServer
  def handle_info(
        %{event: "challenge/request", payload: %{token: token, reply_to: reply_to}},
        state
      ) do
    signature = Client.generate_challenge_signature(token, state.account_key)

    send(reply_to, %{event: "challenge/request", payload: %{signature: signature}})

    {:noreply, state}
  end

  def broadcast(payload) do
    Phoenix.PubSub.broadcast_from!(
      Certified.PubSub,
      self(),
      "certified:certificates_manager",
      %{
        event: "registration/status",
        payload: payload
      }
    )
  end

  defp log(domains, message) do
    Logger.debug("[Certified.Certificate.Registration:#{List.first(domains)}] #{message}")
  end
end
