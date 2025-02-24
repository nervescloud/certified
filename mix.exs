defmodule Certified.MixProject do
  use Mix.Project

  @version "0.1.1"
  @description "An ACME integration built for distributed Phoenix applications."
  @source_url "https://github.com/nervescloud/certified"

  def project do
    [
      app: :certified,
      description: @description,
      version: @version,
      source_url: @source_url,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      package: package(),
      docs: docs(),
      deps: deps()
    ]
  end

  defp docs do
    [
      extras: ["README.md", "CHANGELOG.md"],
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      skip_undefined_reference_warnings_on: ["CHANGELOG.md"]
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: [
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        "lib",
        "mix.exs",
        ".formatter.exs"
      ]
    ]
  end

  def application do
    [
      mod: {Certified.Application, []},
      extra_applications: [:crypto, :sasl, :logger]
    ]
  end

  defp deps do
    [
      {:ex_aws, "~> 2.0", optional: true},
      {:ex_aws_s3, "~> 2.0", optional: true},
      {:ex_doc, "~> 0.18", only: :dev, runtime: false},
      {:jose, "~> 1.11"},
      {:phoenix_pubsub, "~> 2.1"},
      {:process_hub, "~> 0.3.1-alpha"},
      {:plug, "~> 1.16"},
      {:req, "~> 0.5.8"},
      {:thousand_island, "~> 1.3"},
      {:x509, "~> 0.8.10"},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end
end
