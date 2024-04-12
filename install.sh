#!/bin/bash

# Function to detect the user's shell profile
detect_profile() {
  local profile_paths=("$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.config/fish/config.fish" "$HOME/.profile")
  local detected_profile

  for profile_path in "${profile_paths[@]}"; do
    if [ -f "$profile_path" ]; then
      detected_profile="$profile_path"
      break
    fi
  done

  echo "$detected_profile"
}

# Download the Ruby script
wget -q -O solidityinspector.rb https://raw.githubusercontent.com/seeu-inspace/solidityinspector/main/solidityinspector.rb
dos2unix -q solidityinspector.rb

# Move the Ruby script to /usr/local/bin
sudo mv solidityinspector.rb /usr/local/bin


# Determine the user's shell and add the alias accordingly
PROFILE=$(detect_profile)

if [ -n "$PROFILE" ]; then
    # Check if the alias already exists
    if ! grep -q 'alias solidityinspector="ruby /usr/local/bin/solidityinspector.rb"' "$PROFILE"; then
        echo 'alias solidityinspector="ruby /usr/local/bin/solidityinspector.rb"' >> "$PROFILE"
        echo "Alias 'solidityinspector' created successfully! Please restart your shell to apply changes."
    else
        echo "Alias 'solidityinspector' already exists in $PROFILE."
    fi
else
    echo "Unable to detect shell profile. Please add the following alias manually:"
    echo "alias solidityinspector='ruby /usr/local/bin/solidityinspector.rb'"
fi
