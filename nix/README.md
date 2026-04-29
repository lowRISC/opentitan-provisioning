# NixOS CI Machine Configuration

This directory contains the NixOS configuration for the GitHub Actions runner.

## How it Works

This Flake provides two things:
1.  **A System Configuration (`ci-machine`)**: For bare-metal deployment on the CI machine.
2.  **A Development Shell (`default`)**: For developers and CI workflows to get an identical environment without installing tools globally.

## Usage

### For Developers (Local)
To enter the development environment with all tools (Bazel, Go, etc.) ready:
```bash
nix develop
```

### For CI Workflows
To run a command (like a build) using the pinned tools:
```bash
nix develop --command bazelisk build //...
```

### For Bare-Metal Deployment
1.  **Prepare the Target Machine**: Log into `ssh ci@172.16.0.230`.
2.  **Configure Token**:
    ```bash
    sudo mkdir -p /var/lib/secrets
    echo "<TOKEN>" | sudo tee /var/lib/secrets/github-runner-token
    sudo chmod 600 /var/lib/secrets/github-runner-token
    ```
3.  **Deploy**:
    ```bash
    sudo nixos-rebuild switch --flake .#ci-machine
    ```
