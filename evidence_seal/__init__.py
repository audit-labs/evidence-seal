"""evidence-seal — tamper-evident seals for audit evidence packages."""

__version__ = "1.1.0"

# Hash algorithm and manifest format version. Bump MANIFEST_VERSION only on a
# breaking change to the manifest schema so verify can refuse the unknown.
ALGORITHM = "sha256"
MANIFEST_VERSION = 1
