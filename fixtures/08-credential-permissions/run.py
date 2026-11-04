"""Change only the synthetic credential's mode; never open its content."""
import os

os.chmod("/home/.ssh/id_rsa", 0o644)
