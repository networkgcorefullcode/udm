# UDM
<!--
SPDX-FileCopyrightText: 2025 Canonical Ltd
SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
Copyright 2019 free5GC.org

SPDX-License-Identifier: Apache-2.0
-->
[![Go Report Card](https://goreportcard.com/badge/github.com/omec-project/udm)](https://goreportcard.com/report/github.com/omec-project/udm)

# UDM

Implements 3gpp 29.503 specification. Provides service to AUSF, AMF, SMF and
consumes service from UDR. UDM supports SBI interface and any other network
function can use the service.

Compliance of the 5G Network functions can be found at [5G Compliance](https://docs.sd-core.opennetworking.org/main/overview/3gpp-compliance-5g.html)

## UDM block diagram
![UDM Block Diagram](/docs/images/README-UDM.png)

## Repository Structure

Below is a high-level view of the repository and its main components:
```
.
├── consumer                    # Contains logic for inter-NF communication. Handles NF discovery and management to interact with other core network functions.
│   ├── nf_discovery.go
│   ├── nf_management.go
│   └── nf_management_test.go
├── context                     # Manages the UDM runtime context and global data shared across modules.
│   └── context.go
├── dev-container.ps1
├── dev-container.sh
├── DEV_README.md
├── Dockerfile
├── Dockerfile_dev
├── Dockerfile.fast
├── docs                        # Contains documentation assets, such as architecture diagrams or service overviews.
│   └── images
│       ├── README-UDM.png
│       └── README-UDM.png.license
├── eventexposure               # Implements APIs for event exposure service, including creation, update, and deletion of Event Exposure subscriptions.
│   ├── api_create_ee_subscription.go
│   ├── api_delete_ee_subscription.go
│   ├── api_update_ee_subscription.go
│   └── routers.go
├── factory                     # Defines and loads configuration files and templates (udmcfg.yaml, etc.), and initializes the UDM service configuration.
│   ├── config.go
│   ├── factory.go
│   ├── udmcfg_ssm.yaml
│   ├── udmcfg_with_custom_webui_url.yaml
│   ├── udmcfg.yaml
│   └── udm_config_test.go
├── go.mod
├── go.mod.license
├── go.sum
├── go.sum.license
├── httpcallback                # Handles HTTP callbacks for data change notifications between NFs.
│   ├── data_change_notification_to_nf.go
│   └── router.go
├── keydecrypt                  # Provides utilities for key decryption used during authentication and security-related procedures.
│   ├── decrypt.go
│   └── decrypt_test.go
├── LICENSES
│   └── Apache-2.0.txt
├── logger                      # Centralized logging setup for UDM components.
│   └── logger.go
├── Makefile
├── metrics                     # Implements telemetry and metric collection for performance monitoring.
│   └── telemetry.go
├── nfregistration              # Manages Network Function (NF) registration procedures with the NRF.
│   ├── nf_registration.go
│   └── nf_registration_test.go
├── NOTICE.txt
├── parameterprovision          # Implements APIs for updating and managing subscription-related parameters.
│   ├── api_subscription_data_update.go
│   └── routers.go
├── polling                     # Provides mechanisms to periodically poll and update NF configurations.
│   ├── nf_configuration.go
│   └── nf_configuration_test.go
├── producer                    # Contains core UDM service logic, including authentication data generation, subscriber data management, and callback handling.
│   ├── callback
│   │   └── callback.go
│   ├── callback.go
│   ├── event_exposure.go
│   ├── generate_auth_data.go
│   ├── parameter_provision.go
│   ├── subscriber_data_management.go
│   └── ue_context_management.go
├── README.md
├── service                     # Entry point for service initialization and orchestration of UDM components.
│   └── init.go
├── subscribecallback           # Handles subscription callbacks to other network functions for notifications.
│   ├── api_nf_subscribe_notify.go
│   └── router.go
├── subscriberdatamanagement    # Implements the APIs for managing subscriber data (retrieval, creation, modification, deletion, etc.).
│   ├── api_access_and_mobility_subscription_data_retrieval.go
│   ├── api_gpsi_to_supi_translation.go
│   ├── api_providing_acknowledgement_of_steering_of_roaming.go
│   ├── api_providing_acknowledgement_of_ue_parameters_update.go
│   ├── api_retrieval_of_multiple_data_sets.go
│   ├── api_retrieval_of_shared_data.go
│   ├── api_session_management_subscription_data_retrieval.go
│   ├── api_slice_selection_subscription_data_retrieval.go
│   ├── api_smf_selection_subscription_data_retrieval.go
│   ├── api_sms_management_subscription_data_retrieval.go
│   ├── api_sms_subscription_data_retrieval.go
│   ├── api_subscription_creation_for_shared_data.go
│   ├── api_subscription_creation.go
│   ├── api_subscription_deletion_for_shared_data.go
│   ├── api_subscription_deletion.go
│   ├── api_subscription_modification.go
│   ├── api_trace_configuration_data_retrieval.go
│   ├── api_ue_context_in_smf_data_retrieval.go
│   ├── api_ue_context_in_smsf_data_retrieval.go
│   └── routers.go
├── Taskfile.yml
├── test-mirror.txt
├── udm.go
├── udmtests                    # Unit and integration tests for UDM functionality, including NF discovery.
│   └── udm_nf_discovery_test.go
├── ueauthentication            # Defines APIs for user equipment (UE) authentication procedures, including generation and confirmation of authentication data. 
│   ├── api_confirm_auth.go
│   ├── api_generate_auth_data.go
│   └── routers.go
├── uecontextmanagement         # Implements APIs for UE context registration, de-registration, and mobility management in coordination with AMF and SMF.
│   ├── api_amf3_gpp_access_registration_info_retrieval.go
│   ├── api_amf_non3_gpp_access_registration_info_retrieval.go
│   ├── api_amf_registration_for3_gpp_access.go
│   ├── api_amf_registration_for_non3_gpp_access.go
│   ├── api_parameter_update_in_the_amf_registration_for3_gpp_access.go
│   ├── api_parameter_update_in_the_amf_registration_for_non3_gpp_access.go
│   ├── api_smf_deregistration.go
│   ├── api_smf_registration.go
│   ├── api_smsf3_gpp_access_registration_info_retrieval.go
│   ├── api_smsf_deregistration_for3_gpp_access.go
│   ├── api_smsf_deregistration_for_non3_gpp_access.go
│   ├── api_smsf_non3_gpp_access_registration_info_retrieval.go
│   ├── api_smsf_registration_for3_gpp_access.go
│   ├── api_smsf_registration_for_non3_gpp_access.go
│   └── routers.go
├── util                        # Utility functions supporting initialization, NF service search, and general-purpose helpers.
│   ├── init_context.go
│   ├── search_nf_service.go
│   └── util.go
├── vendor                      # Contains vendored Go dependencies to ensure reproducible builds and compatibility with Aether’s codebase.
│   ├── github.com
│   │   ├── antihax
│   │   ├── asaskevich
│   │   ├── beorn7
│   │   ├── bytedance
│   │   ├── cespare
│   │   ├── cloudwego
│   │   ├── davecgh
│   │   ├── gabriel-vasile
│   │   ├── gin-contrib
│   │   ├── gin-gonic
│   │   ├── goccy
│   │   ├── golang-jwt
│   │   ├── google
│   │   ├── go-playground
│   │   ├── h2non
│   │   ├── json-iterator
│   │   ├── klauspost
│   │   ├── leodido
│   │   ├── mattn
│   │   ├── mitchellh
│   │   ├── modern-go
│   │   ├── munnerz
│   │   ├── omec-project
│   │   ├── pelletier
│   │   ├── pkg
│   │   ├── pmezard
│   │   ├── prometheus
│   │   ├── stretchr
│   │   ├── twitchyliquid64
│   │   ├── ugorji
│   │   └── urfave
│   ├── golang.org
│   │   └── x
│   ├── google.golang.org
│   │   └── protobuf
│   ├── gopkg.in
│   │   ├── h2non
│   │   ├── yaml.v2
│   │   └── yaml.v3
│   ├── go.uber.org
│   │   ├── multierr
│   │   └── zap
│   └── modules.txt
├── VERSION
└── VERSION.license

68 directories, 100 files
```

## Configuration and Deployment

**Docker**

To build the container image:
```
task mod-start
task build
task docker-build-fast
```

**Kubernetes**

The standard deployment uses Helm charts from the Aether project. The version of the Chart can be found in the OnRamp repository in the `vars/main.yml` file.


## Quick Navigation

| Goal                                        | Location                                                                   | Description                                               |
| ------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------- |
| **Run the UDM service**                     | `udm.go` / `service/init.go`                                               | Main entry point and service bootstrap.                   |
| **Configure UDM**                           | `factory/udmcfg.yaml`                                                      | Primary configuration file defining service parameters.   |
| **Explore API logic**                       | `subscriberdatamanagement/` / `ueauthentication/` / `uecontextmanagement/` | Implementations of 3GPP service APIs.                     |
| **Study NF discovery/registration**         | `consumer/` / `nfregistration/`                                            | Handles inter-NF communication and registration with NRF. |
| **Enable metrics and monitoring**           | `metrics/telemetry.go`                                                     | Telemetry definitions and metrics collection points.      |
| **Handle logging**                          | `logger/logger.go`                                                         | Central logging configuration for UDM components.         |
| **Modify authentication or security logic** | `producer/` / `keydecrypt/`                                                | Core UDM authentication, decryption, and callback logic.  |
| **Review test cases**                       | `udmtests/` / `consumer/nf_management_test.go`                             | Unit and integration tests for major components.          |
| **Access service documentation**            | `docs/images/README-UDM.png`                                               | Diagram explaining UDM architecture and flow.             |


## Dynamic Network configuration (via webconsole)

UDM polls the webconsole every 5 seconds to fetch the latest PLMN configuration.

### Setting Up Polling

Include the `webuiUri` of the webconsole in the configuration file
```
configuration:
  ...
  webuiUri: https://webui:5001 # or http://webui:5001
  ...
```
The scheme (http:// or https://) must be explicitly specified. If no parameter is specified,
UDM will use `http://webui:5001` by default.

### HTTPS Support

If the webconsole is served over HTTPS and uses a custom or self-signed certificate,
you must install the root CA certificate into the trust store of the UDM environment.

Check the official guide for installing root CA certificates on Ubuntu:
[Install a Root CA Certificate in the Trust Store](https://documentation.ubuntu.com/server/how-to/security/install-a-root-ca-certificate-in-the-trust-store/index.html)

## Reach out to us through

1. #sdcore-dev channel in [Aether Community Slack](https://aether5g-project.slack.com)
2. Raise Github [issues](https://github.com/omec-project/udm/issues/new)
