#!/usr/bin/env bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
IMAGE_NAME="kernagent"
DOCKER_REGISTRY="ghcr.io/karib0u"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
WRAPPER_NAME="kernagent"
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
CONFIG_DIR="${CONFIG_HOME}/kernagent"
CONFIG_FILE="${CONFIG_DIR}/config.env"

# Global variable for model selection result
SELECTED_MODEL=""

# Helper functions
error() {
    echo -e "${RED}✗ Error: $1${NC}" >&2
    exit 1
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

info() {
    echo -e "${CYAN}$1${NC}"
}

warn() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

step() {
    echo -e "\n${BLUE}[$1/$2]${NC} $3"
}

prompt_yn() {
    local prompt="$1"
    local default="${2:-n}"
    local response
    
    if [[ "$default" == "y" ]]; then
        read -r -p "$(echo -e ${YELLOW}${prompt} [Y/n]:${NC} )" response
        [[ -z "$response" || "$response" =~ ^[Yy]$ ]]
    else
        read -r -p "$(echo -e ${YELLOW}${prompt} [y/N]:${NC} )" response
        [[ "$response" =~ ^[Yy]$ ]]
    fi
}

prompt_input() {
    local prompt="$1"
    local default="$2"
    local value
    
    if [[ -n "$default" ]]; then
        read -r -p "$(echo -e ${CYAN}${prompt} [${default}]:${NC} )" value
        echo "${value:-$default}"
    else
        while true; do
            read -r -p "$(echo -e ${CYAN}${prompt}:${NC} )" value
            [[ -n "$value" ]] && echo "$value" && return 0
            warn "Input cannot be empty"
        done
    fi
}

# Fetch and display models from OpenAI-compatible endpoint
# Stores result in global SELECTED_MODEL variable
select_model_from_api() {
    local base_url="$1"
    local api_key="$2"
    local example_models="$3"
    local default_model="$4"
    
    SELECTED_MODEL=""
    
    # Convert host.docker.internal to localhost for discovery
    local query_url="${base_url}"
    if [[ "$query_url" == *"host.docker.internal"* ]] || [[ "$query_url" == *"host.containers.internal"* ]]; then
        query_url="${query_url//host.docker.internal/localhost}"
        query_url="${query_url//host.containers.internal/localhost}"
        info "Using localhost for model discovery (kernagent will use ${base_url})"
    fi
    
    local models_endpoint="${query_url%/}/models"
    local models=()
    
    # Check requirements
    if ! command -v curl &>/dev/null; then
        warn "curl not found, skipping auto-detection"
        if [[ -n "$example_models" ]]; then
            info "Examples: ${example_models}"
        fi
        SELECTED_MODEL=$(prompt_input "Enter model name" "$default_model")
        return 0
    fi
    
    # Create temp file
    local tmp_file
    tmp_file=$(mktemp 2>/dev/null) || {
        warn "Cannot create temp file"
        SELECTED_MODEL=$(prompt_input "Enter model name" "$default_model")
        return 0
    }
    
    # Prepare curl command with HTTP code output
    local curl_args=(-sS -w "%{http_code}" -o "$tmp_file" --max-time 10 -H "Content-Type: application/json")
    if [[ -n "$api_key" && "$api_key" != "not-needed" ]]; then
        curl_args+=(-H "Authorization: Bearer ${api_key}")
    fi
    curl_args+=("$models_endpoint")
    
    # Fetch models
    info "Querying for available models..."
    local http_code
    http_code=$(curl "${curl_args[@]}" 2>/dev/null || echo "000")
    
    if [[ "$http_code" != "200" ]] || [[ ! -s "$tmp_file" ]]; then
        warn "Model listing failed (HTTP ${http_code})"
        rm -f "$tmp_file"
        if [[ -n "$example_models" ]]; then
            info "Examples: ${example_models}"
        fi
        SELECTED_MODEL=$(prompt_input "Enter model name" "$default_model")
        return 0
    fi
    
    # Parse models from JSON
    local parsed_models=""
    
    # Try with Python first (most reliable)
    if command -v python3 &>/dev/null || command -v python &>/dev/null; then
        local python_bin=$(command -v python3 2>/dev/null || command -v python 2>/dev/null)
        parsed_models=$("$python_bin" <<PY "$tmp_file"
import json, sys
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        data = json.load(f)
    models = data.get('data', [])
    for m in models:
        if isinstance(m, dict) and 'id' in m:
            print(m['id'].strip())
except:
    pass
PY
)
    fi
    
    # Fallback to grep/sed if Python failed
    if [[ -z "$parsed_models" ]]; then
        parsed_models=$(grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' "$tmp_file" 2>/dev/null | sed 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "")
    fi
    
    rm -f "$tmp_file"
    
    # Store models in array
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)  # Trim whitespace
        [[ -n "$line" ]] && models+=("$line")
    done <<< "$parsed_models"
    
    if [[ ${#models[@]} -eq 0 ]]; then
        warn "No models found in response"
        if [[ -n "$example_models" ]]; then
            info "Examples: ${example_models}"
        fi
        SELECTED_MODEL=$(prompt_input "Enter model name" "$default_model")
        return 0
    fi
    
    # Display models with pagination
    echo ""
    success "Found ${#models[@]} model(s)"
    
    local page_size=20
    local current_page=0
    local total_pages=$(( (${#models[@]} + page_size - 1) / page_size ))
    
    while true; do
        local start_idx=$((current_page * page_size))
        local end_idx=$((start_idx + page_size))
        [[ $end_idx -gt ${#models[@]} ]] && end_idx=${#models[@]}
        
        echo ""
        echo -e "${CYAN}Showing models $((start_idx + 1))-${end_idx} of ${#models[@]}${NC}"
        echo ""
        
        for ((i=start_idx; i<end_idx; i++)); do
            printf "  ${CYAN}%2d)${NC} %s\n" "$((i + 1))" "${models[$i]}"
        done
        
        echo ""
        if [[ $end_idx -lt ${#models[@]} ]]; then
            echo -e "${YELLOW}[n] Next page  |  [p] Previous page  |  [number] Select  |  [text] Enter model name${NC}"
        else
            if [[ $current_page -gt 0 ]]; then
                echo -e "${YELLOW}[p] Previous page  |  [number] Select  |  [text] Enter model name${NC}"
            else
                echo -e "${YELLOW}[number] Select model  |  [text] Enter model name${NC}"
            fi
        fi
        
        local selection=""
        read -r -p "> " selection
        selection=$(echo "$selection" | xargs | tr '[:upper:]' '[:lower:]')
        
        if [[ -z "$selection" ]]; then
            warn "Selection cannot be empty"
            continue
        fi
        
        # Handle pagination commands
        if [[ "$selection" == "n" ]] || [[ "$selection" == "next" ]]; then
            if [[ $end_idx -lt ${#models[@]} ]]; then
                ((current_page++))
                continue
            else
                warn "Already on last page"
                continue
            fi
        fi
        
        if [[ "$selection" == "p" ]] || [[ "$selection" == "prev" ]] || [[ "$selection" == "previous" ]]; then
            if [[ $current_page -gt 0 ]]; then
                ((current_page--))
                continue
            else
                warn "Already on first page"
                continue
            fi
        fi
        
        # Check if numeric selection
        if [[ "$selection" =~ ^[0-9]+$ ]]; then
            local idx=$((selection - 1))
            if [[ $idx -ge 0 && $idx -lt ${#models[@]} ]]; then
                SELECTED_MODEL="${models[$idx]}"
                return 0
            else
                warn "Enter a number between 1 and ${#models[@]}"
                continue
            fi
        fi
        
        # Manual entry
        SELECTED_MODEL="$selection"
        return 0
    done
}

# Header
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      kernagent Installation            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"

# Step 1: Check Docker
step 1 5 "Checking Docker..."
command -v docker &>/dev/null || error "Docker not found. Install from: https://docs.docker.com/get-docker/"
docker info &>/dev/null || error "Docker daemon not running. Please start Docker."
success "Docker ready"

# Step 2: Get repository
step 2 5 "Preparing repository..."
if [[ ! -f "Dockerfile" ]]; then
    command -v git &>/dev/null || error "Git not found. Please install git or clone manually."
    
    TEMP_DIR=$(mktemp -d)
    info "Cloning to ${TEMP_DIR}..."
    git clone --quiet "https://github.com/Karib0u/kernagent.git" "${TEMP_DIR}" || error "Failed to clone repository"
    cd "${TEMP_DIR}"
    trap "cd / && rm -rf '${TEMP_DIR}'" EXIT
fi
success "Repository ready"

# Step 3: Build/Pull image
step 3 5 "Setting up Docker image..."
HOST_ARCH=$(docker info --format '{{.Architecture}}' 2>/dev/null | tr '[:upper:]' '[:lower:]')

if [[ "$HOST_ARCH" =~ ^(amd64|x86_64)$ ]]; then
    info "Pulling pre-built image..."
    if docker pull "${DOCKER_REGISTRY}/${IMAGE_NAME}:latest" &>/dev/null; then
        docker tag "${DOCKER_REGISTRY}/${IMAGE_NAME}:latest" "${IMAGE_NAME}:latest"
        success "Image pulled from registry"
    else
        warn "Pull failed, building locally..."
        docker build -q -t "${IMAGE_NAME}:latest" . || error "Docker build failed"
        success "Image built locally"
    fi
else
    info "Building for ${HOST_ARCH} architecture..."
    docker build -q -t "${IMAGE_NAME}:latest" . || error "Docker build failed"
    success "Image built for ${HOST_ARCH}"
fi

# Step 4: Install CLI wrapper
step 4 5 "Installing CLI wrapper..."

# Confirm install directory
if prompt_yn "Install to ${INSTALL_DIR}?" "y"; then
    :
else
    INSTALL_DIR=$(prompt_input "Enter installation directory" "$HOME/.local/bin")
    mkdir -p "$INSTALL_DIR" || error "Failed to create directory"
fi

# Create wrapper
cat > "/tmp/${WRAPPER_NAME}" << 'WRAPPER_EOF'
#!/usr/bin/env bash
set -e

IMAGE_NAME="kernagent"
DOCKER_REGISTRY="ghcr.io/karib0u"
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
CONFIG_FILE="${KERNAGENT_CONFIG:-${CONFIG_HOME}/kernagent/config.env}"
CONFIG_FILE="${CONFIG_FILE/#\~/$HOME}"
CONTAINER_CONFIG_PATH="/config/config.env"

# Check Docker
docker info &>/dev/null 2>&1 || {
    echo "Error: Docker daemon not running" >&2
    exit 1
}

# Check image
if ! docker image inspect "${IMAGE_NAME}" &>/dev/null; then
    echo "Pulling ${IMAGE_NAME}..." >&2
    docker pull "${DOCKER_REGISTRY}/${IMAGE_NAME}:latest" &>/dev/null && \
    docker tag "${DOCKER_REGISTRY}/${IMAGE_NAME}:latest" "${IMAGE_NAME}" || {
        echo "Error: Image not found. Run install script again." >&2
        exit 1
    }
fi

# Parse arguments for binary path
BINARY_PATH=""
for arg in "$@"; do
    if [[ -f "$arg" ]] || [[ "$arg" =~ \.(exe|bin|dll|so|elf)$ ]]; then
        BINARY_PATH="$arg"
        break
    fi
done

# Setup volume mounts
if [[ -n "$BINARY_PATH" ]]; then
    BINARY_ABS="$(cd "$(dirname "$BINARY_PATH")" && pwd)/$(basename "$BINARY_PATH")"
    BINARY_DIR="$(dirname "$BINARY_ABS")"
    BINARY_NAME="$(basename "$BINARY_ABS")"
    VOLUME_ARGS=("-v" "${BINARY_DIR}:/data")
    
    # Update args with container path
    ARGS=()
    for arg in "$@"; do
        if [[ "$arg" == "$BINARY_PATH" ]]; then
            ARGS+=("/data/${BINARY_NAME}")
        else
            ARGS+=("$arg")
        fi
    done
else
    VOLUME_ARGS=("-v" "$(pwd):/data")
    ARGS=("$@")
fi

# Mount shared config if available
if [[ -f "$CONFIG_FILE" ]]; then
    VOLUME_ARGS+=("-v" "${CONFIG_FILE}:${CONTAINER_CONFIG_PATH}:ro")
else
    echo "Warning: kernagent config not found at ${CONFIG_FILE}" >&2
fi

# Environment variables
ENV_ARGS=()
[[ -n "$OPENAI_API_KEY" ]] && ENV_ARGS+=("-e" "OPENAI_API_KEY=$OPENAI_API_KEY")
[[ -n "$OPENAI_BASE_URL" ]] && ENV_ARGS+=("-e" "OPENAI_BASE_URL=$OPENAI_BASE_URL")
[[ -n "$OPENAI_MODEL" ]] && ENV_ARGS+=("-e" "OPENAI_MODEL=$OPENAI_MODEL")
[[ -f "$CONFIG_FILE" ]] && ENV_ARGS+=("-e" "KERNAGENT_CONFIG=${CONTAINER_CONFIG_PATH}")

# Run container
exec docker run --rm \
    "${VOLUME_ARGS[@]}" \
    "${ENV_ARGS[@]}" \
    "${IMAGE_NAME}" \
    "${ARGS[@]}"
WRAPPER_EOF

chmod +x "/tmp/${WRAPPER_NAME}"

# Install wrapper
if [[ -w "$INSTALL_DIR" ]]; then
    mv "/tmp/${WRAPPER_NAME}" "${INSTALL_DIR}/${WRAPPER_NAME}"
else
    sudo mv "/tmp/${WRAPPER_NAME}" "${INSTALL_DIR}/${WRAPPER_NAME}"
    sudo chmod +x "${INSTALL_DIR}/${WRAPPER_NAME}"
fi

success "Installed to ${INSTALL_DIR}/${WRAPPER_NAME}"

# Step 5: Configure LLM
step 5 5 "LLM Configuration"

if [[ -f "$CONFIG_FILE" ]]; then
    info "Existing config found at ${CONFIG_FILE}"
    if ! prompt_yn "Reconfigure LLM settings?" "n"; then
        success "Using existing configuration"
        SKIP_CONFIG=true
    fi
fi

if [[ "$SKIP_CONFIG" != "true" ]]; then
    if prompt_yn "Configure LLM provider now?" "y"; then
        echo ""
        info "Select provider:"
        echo "  1) OpenAI (GPT-4)"
        echo "  2) Google (Gemini)"
        echo "  3) Anthropic (Claude)"
        echo "  4) Local (LM Studio/Ollama)"
        echo "  5) Custom OpenAI-compatible"
        echo "  6) Skip (configure later)"
        
        read -r -p "> " choice
        
        case "$choice" in
            1)
                API_KEY=$(prompt_input "OpenAI API key")
                BASE_URL="https://api.openai.com/v1"
                select_model_from_api "$BASE_URL" "$API_KEY" "gpt-4o, gpt-4o-mini, gpt-3.5-turbo" "gpt-4o"
                MODEL="$SELECTED_MODEL"
                ;;
            2)
                API_KEY=$(prompt_input "Google AI API key")
                BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
                select_model_from_api "$BASE_URL" "$API_KEY" "gemini-2.0-flash-exp, gemini-1.5-pro, gemini-1.5-flash" "gemini-2.0-flash-exp"
                MODEL="$SELECTED_MODEL"
                ;;
            3)
                API_KEY=$(prompt_input "Anthropic API key")
                BASE_URL="https://api.anthropic.com/v1"
                select_model_from_api "$BASE_URL" "$API_KEY" "claude-3-5-sonnet-20241022, claude-3-opus-20240229" "claude-3-5-sonnet-20241022"
                MODEL="$SELECTED_MODEL"
                ;;
            4)
                BASE_URL=$(prompt_input "Base URL" "http://host.docker.internal:1234/v1")
                API_KEY=$(prompt_input "API key (leave empty if not needed)" "not-needed")
                [[ -z "$API_KEY" ]] && API_KEY="not-needed"
                select_model_from_api "$BASE_URL" "$API_KEY" "llama-3.2-3b-instruct, qwen2.5-coder:7b" "llama-3.2-3b-instruct"
                MODEL="$SELECTED_MODEL"
                ;;
            5)
                BASE_URL=$(prompt_input "Base URL (must support /v1/chat/completions)")
                API_KEY=$(prompt_input "API key")
                select_model_from_api "$BASE_URL" "$API_KEY" "" ""
                MODEL="$SELECTED_MODEL"
                ;;
            *)
                warn "Skipping configuration"
                SKIP_CONFIG=true
                ;;
        esac
        
        if [[ "$SKIP_CONFIG" != "true" ]]; then
            mkdir -p "${CONFIG_DIR}"
            cat > "${CONFIG_FILE}" << EOF
OPENAI_API_KEY=${API_KEY}
OPENAI_BASE_URL=${BASE_URL}
OPENAI_MODEL=${MODEL}
DEBUG=false
EOF
            success "Configuration saved to ${CONFIG_FILE}"
            info "Set KERNAGENT_CONFIG=${CONFIG_FILE} to override the default path."
        fi
    else
        info "You can create ${CONFIG_FILE} manually later"
    fi
fi

# Final verification
if ! command -v "${WRAPPER_NAME}" &>/dev/null && [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    warn "Add to PATH: export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

# Success
echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    Installation Complete! 🎉           ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Quick Start:${NC}"
echo "  ${WRAPPER_NAME} --help"
echo "  ${WRAPPER_NAME} summary binary.exe"
echo "  ${WRAPPER_NAME} ask binary.exe \"What does this do?\""
echo ""
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${CYAN}Tip: Create ${CONFIG_FILE} with:${NC}"
    echo "  OPENAI_API_KEY=your-key"
    echo "  OPENAI_BASE_URL=https://api.openai.com/v1"
    echo "  OPENAI_MODEL=gpt-4o"
    echo ""
    echo "Then rerun ${WRAPPER_NAME} commands (the file will be mounted into the container)."
fi
