"""A local RFC 3161 Time-Stamp Authority for the end-to-end demo.

Mints genuinely CMS-signed timestamp tokens offline so scripts/e2e.sh can
exercise the full timestamp flow — including signature verification — without a
network or a public TSA. It reuses the token issuer from the test suite.

Usage: python scripts/_local_tsa.py <manifest_id> <out_dir> [--no-eku] [--expired]
Writes <out_dir>/resp.tsr (a TimeStampResp) and <out_dir>/tsa.pem (the cert).
"""

import datetime
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve()
_REPO = _HERE.parent.parent
sys.path.insert(0, str(_REPO / "tests"))
sys.path.insert(0, str(_REPO))

from test_timestamp import issue_signed_token


def main() -> None:
    manifest_id, out_dir = sys.argv[1], pathlib.Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    eku = "--no-eku" not in sys.argv
    validity = None
    if "--expired" in sys.argv:
        validity = (
            datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
            datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc),
        )
    token, cert = issue_signed_token(manifest_id, timestamping_eku=eku, validity=validity)
    (out_dir / "resp.tsr").write_bytes(token)
    (out_dir / "tsa.pem").write_bytes(cert)


if __name__ == "__main__":
    main()
