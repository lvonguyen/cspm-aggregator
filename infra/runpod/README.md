# RunPod 2x B200 GPU Configuration

SSH configuration for RunPod instances with 2x NVIDIA B200 GPUs, integrated with 1Password for secure credential management.

## Hardware Specification

| Component | Specification |
|-----------|---------------|
| GPU | 2x NVIDIA B200 (192GB HBM3e each) |
| Total VRAM | 384GB |
| Interconnect | NVLink 5.0 (1.8TB/s bidirectional) |
| Use Case | Large model training, inference |

## Prerequisites

1. **1Password CLI** installed and authenticated
   ```bash
   # macOS
   brew install 1password-cli

   # Linux
   curl -sS https://downloads.1password.com/linux/keys/1password.asc | \
     sudo gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/amd64 stable main" | \
     sudo tee /etc/apt/sources.list.d/1password.list
   sudo apt update && sudo apt install 1password-cli
   ```

2. **1Password Sign-in**
   ```bash
   eval $(op signin)
   ```

## 1Password Setup

Create a secure note in 1Password with the following structure:

| Field | Description |
|-------|-------------|
| **Vault** | `Private` |
| **Item Name** | `RunPod-B200-SSH` |
| **Field: private_key** | Your RunPod SSH private key (full PEM content) |
| **Field: pod_id** | (Optional) RunPod Pod ID for reference |
| **Field: endpoint** | (Optional) RunPod SSH endpoint |

### Creating the 1Password Item

```bash
# Generate SSH keypair (if needed)
ssh-keygen -t ed25519 -f ~/.ssh/runpod-b200-temp -N "" -C "runpod-b200"

# Create 1Password item with the private key
op item create \
  --category="Secure Note" \
  --vault="Private" \
  --title="RunPod-B200-SSH" \
  "private_key[password]=$(cat ~/.ssh/runpod-b200-temp)" \
  "pod_id[text]=YOUR_POD_ID" \
  "endpoint[text]=ssh.runpod.io"

# Add the public key to your RunPod account settings
cat ~/.ssh/runpod-b200-temp.pub

# Clean up temp files
rm ~/.ssh/runpod-b200-temp ~/.ssh/runpod-b200-temp.pub
```

## Quick Start

```bash
# 1. Retrieve SSH key from 1Password and configure SSH
cd infra/runpod/ssh
./get-ssh-key.sh

# 2. Connect to your RunPod B200 instance
ssh runpod-b200

# 3. Verify GPUs
nvidia-smi
```

## SSH Profiles

| Profile | Use Case |
|---------|----------|
| `runpod-b200` | Standard SSH connection |
| `runpod-b200-tunnel` | Port forwarding (Jupyter: 8888, TensorBoard: 6006) |
| `runpod-b200-web` | Forced TTY for web terminal compatibility |

### Port Forwarding (for Jupyter/TensorBoard)

```bash
# Connect with tunneling profile
ssh runpod-b200-tunnel

# Access locally:
# - Jupyter: http://localhost:8888
# - TensorBoard: http://localhost:6006
# - NCCL: localhost:29500
```

## File Structure

```
infra/runpod/
├── README.md           # This file
└── ssh/
    ├── config          # SSH config for RunPod hosts
    └── get-ssh-key.sh  # 1Password key retrieval script
```

## Refreshing SSH Key

If you rotate your SSH key in 1Password:

```bash
./ssh/get-ssh-key.sh --refresh
```

## Troubleshooting

### Connection refused
- Ensure your RunPod pod is running
- Check that your public key is added to RunPod account settings

### 1Password errors
```bash
# Re-authenticate
eval $(op signin)

# Verify item exists
op item get "RunPod-B200-SSH" --vault="Private"
```

### GPU not detected
```bash
# Check NVIDIA drivers on pod
ssh runpod-b200 "nvidia-smi"

# Check CUDA
ssh runpod-b200 "nvcc --version"
```

## Multi-GPU Training Notes

The 2x B200 configuration supports:
- PyTorch DDP across both GPUs
- DeepSpeed ZeRO stages 1-3
- FSDP with NVLink-optimized sharding
- Megatron-LM tensor parallelism

Example distributed launch:
```bash
ssh runpod-b200 "torchrun --nproc_per_node=2 train.py"
```
