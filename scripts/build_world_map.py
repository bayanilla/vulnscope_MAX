"""Build the Olive Drab SVG from Natural Earth 1:110m GeoJSON files.

Usage: python3 scripts/build_world_map.py LAND.geojson COUNTRIES.geojson
The resulting SVG is written to vulnflow/static/world_map.svg.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

WIDTH, HEIGHT = 1600, 900
TOP, BOTTOM = 85, -60
OUTPUT = Path(__file__).resolve().parents[1] / "vulnflow" / "static" / "world_map.svg"


def rings(geometry):
    coordinates = geometry["coordinates"]
    if geometry["type"] == "Polygon":
        yield from coordinates
    elif geometry["type"] == "MultiPolygon":
        for polygon in coordinates:
            yield from polygon


def paths(source):
    data = json.loads(Path(source).read_text(encoding="utf-8"))
    for feature in data["features"]:
        for ring in rings(feature["geometry"]):
            points = []
            for lon, lat, *_ in ring:
                x = (lon + 180) * WIDTH / 360
                y = (TOP - lat) * HEIGHT / (TOP - BOTTOM)
                points.append(f"{x:.1f},{y:.1f}")
            if len(points) > 2:
                yield "M" + "L".join(points) + "Z"


def main(land_file, countries_file):
    land = "".join(paths(land_file))
    countries = "".join(paths(countries_file))
    grid = []
    for lon in range(-150, 180, 30):
        x = (lon + 180) * WIDTH / 360
        grid.append(f'<path d="M{x:.1f} 0V{HEIGHT}"/>')
    for lat in range(-60, 90, 30):
        y = (TOP - lat) * HEIGHT / (TOP - BOTTOM)
        grid.append(f'<path d="M0 {y:.1f}H{WIDTH}"/>')
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" fill="none">\n'
           '<!-- Natural Earth 1:110m land and country boundaries; public domain. -->\n'
           f'<g stroke="#c3b777" stroke-opacity=".07" stroke-width="1">{"".join(grid)}</g>\n'
           f'<path d="{land}" fill="#c3b777" fill-opacity=".075" stroke="#d4c88a" stroke-opacity=".42" stroke-width="1.8"/>\n'
           f'<path d="{countries}" stroke="#d4c88a" stroke-opacity=".28" stroke-width=".9"/>\n'
           '</svg>\n')
    OUTPUT.write_text(svg, encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python3 scripts/build_world_map.py LAND.geojson COUNTRIES.geojson")
    main(sys.argv[1], sys.argv[2])
