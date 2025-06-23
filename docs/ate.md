# Automated Test Equipment (ATE) Client

The Automated Test Equipment (ATE) client library and associated test programs
are used to drive provisioning flows for OpenTitan devices. The client
communicates with one or more
[Provisioning Appliance (PA)](https://github.com/lowRISC/opentitan-provisioning/wiki/pa)
servers to perform secure provisioning operations.

## Client-Side Load Balancing and Failover

The ATE client library supports gRPC client-side load balancing, allowing it
to distribute requests across multiple Provisioning Appliance (PA) server
instances. This enhances reliability and scalability.

### Enabling Load Balancing

To enable load balancing, you must provide a list of server addresses in a
gRPC-compliant format via the `--pa_target` command-line argument when running
a test program (e.g., `cp` or `ft`).

*   **Target URI Format**: The target should be specified using gRPC's
    name-syntax.
    *   For IPv4: `ipv4:<ip_addr1>:<port1>,<ip_addr2>:<port2>,...`
    *   For IPv6: `ipv6:[<ip_addr1>]:<port1>,[<ip_addr2>]:<port2>,...`

    Example: `--pa_target="ipv4:10.0.0.1:50051,10.0.0.2:50051"`

### Load Balancing Policies

You can select a load balancing policy using the `--load_balancing_policy`
argument. If unspecified, gRPC's default (`pick_first`) is used.

*   `pick_first` (Default): The client attempts to connect to the first
    address in the list. All RPCs are sent to this single server. If the
    connection fails, it will try the next address in the list. This policy
    provides basic failover but does not distribute load.
*   `round_robin`: The client connects to all servers in the list and
    distributes RPCs across them in a round-robin fashion. This policy
    provides both load balancing and high-availability failover.

### Failover Scenarios

The behavior of the client during server outages depends on the configured
policy.

*   **Partial Outage (with `round_robin`)**: If one server in the pool becomes
    unavailable, the gRPC runtime will automatically detect the failed
    connection and temporarily remove it from the pool of healthy endpoints.
    Subsequent API calls will be transparently routed to the remaining healthy
    servers. From the caller's perspective, the operations will continue to
    succeed without any errors.

*   **Total Outage**: If all server endpoints become unavailable, any API call
    made through the library will fail.
    *   The C API functions (e.g., `InitSession`, `DeriveTokens`) will return a
        non-zero status code. This code will correspond to the gRPC status
        code `UNAVAILABLE` (14).
    *   Callers must check the return value of every function call to handle
        this scenario gracefully. A persistent failure with this status code
        indicates that the client cannot reach any of the configured
        provisioning servers.

## Client Lifecycle and Resource Management

The ATE client is a heavyweight object that manages the underlying gRPC
channel, including network connections and load balancing state.

### Creating and Destroying Client Instances

Each call to `CreateClient` initializes and returns a pointer to a new,
independent client instance. This process is computationally expensive as it
involves:

-   Setting up a new gRPC channel.
-   Establishing new TCP connections to the server(s).
-   Performing a TLS handshake (if mTLS is enabled).
-   Resolving server addresses.

Because of this overhead, for applications connecting to a single endpoint or a
load-balanced group of endpoints, it is recommended to create one client
instance and reuse it for multiple RPC calls.

The caller is responsible for cleaning up every client instance that is created.
For each `ate_client_ptr` returned by `CreateClient`, a corresponding call to
`DestroyClient` must be made when the client is no longer needed. This will
tear down the network connections and free associated resources.

### Using Multiple Clients for Manual Server Selection

While the client library supports gRPC-based load balancing for connecting to a
pool of servers, you can also manage connections to multiple, distinct
endpoints manually. This is achieved by creating multiple client instances.

This approach is useful when you need to connect to different provisioning
environments (e.g., staging vs. production) or to specific servers for
diagnostic purposes, without relying on gRPC's load balancing policies.

To do this, call `CreateClient` for each server you want to connect to,
providing a *single* server address in the `pa_target` option for each.

**Example Scenario:** Connecting to two separate PA servers.

```c
// C/C++ Example Snippet
ate_client_ptr client_for_server_1 = NULL;
ate_client_ptr client_for_server_2 = NULL;

client_options_t opts1 = { .pa_target = "ipv4:10.0.0.1:50051", /* other options */ };
client_options_t opts2 = { .pa_target = "ipv4:10.0.0.2:50051", /* other options */ };

// Create a client for the first server
int status = CreateClient(&client_for_server_1, &opts1);
if (status != 0) { /* handle error */ }

// Create a client for the second server
status = CreateClient(&client_for_server_2, &opts2);
if (status != 0) { /* handle error */ }

// ... use both clients to make RPC calls ...
// e.g., InitSession(client_for_server_1, "sku1", ...);
// e.g., InitSession(client_for_server_2, "sku2", ...);

// At the end of the session, destroy both clients
DestroyClient(client_for_server_1);
DestroyClient(client_for_server_2);
```

**Important:** You must ensure that `DestroyClient` is called for every client
instance created to avoid resource leaks.

## Monitoring and Debugging

While the ATE client library does not expose a direct API to query the health
of individual server endpoints, it is possible to monitor the underlying gRPC
channel's behavior using gRPC's built-in tracing capabilities. This is an
effective method for debugging connection issues and observing the load
balancer's real-time behavior.

### Enabling gRPC Tracing

You can enable detailed logging by setting environment variables in your shell
before launching the application that uses the ATE client library.

```bash
# Enable tracing for connectivity state, resolvers, and load balancing
export GRPC_TRACE=connectivity_state,resolver,load_balancer

# Set the logging verbosity for maximum detail
export GRPC_VERBOSITY=DEBUG
```

### Interpreting the Output

When tracing is enabled, the gRPC runtime will print detailed logs to `stderr`.
If a server in the load balancing pool becomes unavailable, you will see log
entries showing the subchannel's state changing from `READY` to `CONNECTING`
and then to `TRANSIENT_FAILURE`. When the server becomes available again, the
logs will show the state transitioning back to `READY`.

This provides a definitive, real-time view of the connection health from the
client's perspective and is an useful tool in active debugging sessions.

## Running an ATE Test Program

Before running, ensure you have:
*   Generated the required
    [endpoint certificates](https://github.com/lowRISC/opentitan-provisioning/wiki/auth#endpoint-certificates).
*   Started one or more
    [PA servers](https://github.com/lowRISC/opentitan-provisioning/wiki/pa#start-pa-server).

The following example shows how to run the `ft` test program with load
balancing enabled against two PA servers.

```console
# The specific test program can be :cp or :ft
bazelisk run //src/ate/test_programs:cp -- \
    --pa_target="ipv4:localhost:5001,localhost:5002" \
    --load_balancing_policy="round_robin" \
    --enable_mtls \
    --client_key=$(pwd)/config/certs/out/ate-client-key.pem \
    --client_cert=$(pwd)/config/certs/out/ate-client-cert.pem \
    --ca_root_certs=$(pwd)/config/certs/out/ca-cert.pem \
    --sku="sival" \
    --sku_auth_pw="test_password"
```

## Read More

*   [Provisioning Appliance](https://github.com/lowRISC/opentitan-provisioning/wiki/pa)
*   [Documentation index](https://github.com/lowRISC/opentitan-provisioning/wiki/Home)
