
from pathlib import Path
import csv, datetime, tempfile, os

def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

def write_csv(rows, out_path: Path, fieldnames: list[str]):
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # atomic write

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8-sig", newline="",
                                    dir=out_path.parent) as tf:
        w = csv.DictWriter(tf, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})
        tmp_name = tf.name
    os.replace(tmp_name, out_path)  # atomic move

def make_outpath(tool: str, out_dir: Path, label: str | None, suffix="csv") -> Path:

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{tool}"
    if label:
        base += f"_{label}"
    return out_dir / f"{base}_{ts}.{suffix}"
