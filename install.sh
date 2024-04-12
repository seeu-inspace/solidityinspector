#!/bin/bash

# Function to detect the user's shell profile
detect_profile() {
  if [ -n "${PROFILE}" ] && [ -f "${PROFILE}" ]; then
    echo "${PROFILE}"
    return
  fi

  local DETECTED_PROFILE
  DETECTED_PROFILE=''
  local SHELLTYPE
  SHELLTYPE="$(basename "/$SHELL")"

  if [ "$SHELLTYPE" = "bash" ]; then
    if [ -f "$HOME/.bashrc" ]; then
      DETECTED_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then
      DETECTED_PROFILE="$HOME/.bash_profile"
    fi
  elif [ "$SHELLTYPE" = "zsh" ]; then
    DETECTED_PROFILE="$HOME/.zshrc"
  elif [ "$SHELLTYPE" = "fish" ]; then
    DETECTED_PROFILE="$HOME/.config/fish/config.fish"
  fi

  if [ -z "$DETECTED_PROFILE" ]; then
    if [ -f "$HOME/.profile" ]; then
      DETECTED_PROFILE="$HOME/.profile"
    elif [ -f "$HOME/.bashrc" ]; then
      DETECTED_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then
      DETECTED_PROFILE="$HOME/.bash_profile"
    elif [ -f "$HOME/.zshrc" ]; then
      DETECTED_PROFILE="$HOME/.zshrc"
    elif [ -f "$HOME/.config/fish/config.fish" ]; then
      DETECTED_PROFILE="$HOME/.config/fish/config.fish"
    fi
  fi

  if [ ! -z "$DETECTED_PROFILE" ]; then
    echo "$DETECTED_PROFILE"
  fi
}

# Download the Ruby script
wget https://raw.githubusercontent.com/seeu-inspace/solidityinspector/main/solidityinspector.rb
dos2unix solidityinspector.rb

# Move the Ruby script to /usr/local/bin
sudo mv solidityinspector.rb /usr/local/bin

# Make the script executable
sudo chmod +x /usr/local/bin/solidityinspector.rb

# Determine the user's shell and add the alias accordingly
PROFILE=$(detect_profile)

if [ -n "$PROFILE" ]; then
    # Check if the alias already exists
    if ! grep -q 'alias solidityinspector="ruby /usr/local/bin/solidityinspector.rb"' "$PROFILE"; then
        echo 'alias solidityinspector="ruby /usr/local/bin/solidityinspector.rb"' >> "$PROFILE"
        source "$PROFILE"
        echo "Alias 'solidityinspector' created successfully!"
    else
        echo "Alias 'solidityinspector' already exists in $PROFILE."
    fi
else
    echo "Unable to detect shell profile. Please add the following alias manually:"
    echo "alias solidityinspector='ruby /usr/local/bin/solidityinspector.rb'"
fi
