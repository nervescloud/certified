defmodule Certified.Acme.Responses do
  defmodule Account do
    defstruct account_location: nil,
              contact: nil,
              status: nil

    @type t ::
            %__MODULE__{
              account_location: String.t(),
              contact: [String.t()],
              status: String.t()
            }
  end

  defmodule Order do
    defstruct order_location: nil,
              authorizations: nil,
              expires: nil,
              finalize_url: nil,
              identifiers: nil,
              status: nil,
              certificate_url: nil

    @type t ::
            %__MODULE__{
              order_location: String.t(),
              authorizations: [String.t()],
              expires: DateTime.t(),
              finalize_url: String.t(),
              identifiers: [map()],
              status: String.t(),
              certificate_url: String.t()
            }
  end

  defmodule Authorization do
    defstruct authorization_location: nil,
              status: nil,
              expires: nil,
              identifier: nil,
              challenges: nil

    @type t ::
            %__MODULE__{
              authorization_location: String.t(),
              status: String.t(),
              expires: DateTime.t(),
              identifier: map(),
              challenges: [map()]
            }
  end
end
