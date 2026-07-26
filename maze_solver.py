"""
Standalone BFS solver for the "Solve a Generated Maze Offline" question.

Usage:
    python3 maze_solver.py path/to/your-maze.json

Expects a JSON file shaped like:
    {
      "width": ..., "height": ...,
      "start": [x, y], "end": [x, y],
      "openMask": [[...], [...], ...]   # openMask[y][x], 4-bit: U=1 R=2 D=4 L=8
    }

Prints the shortest move string (U/D/L/R) from start to end, and validates
it before printing.
"""

import json
import sys
from collections import deque


DIRS = {
    'U': (0, -1, 1),
    'R': (1, 0, 2),
    'D': (0, 1, 4),
    'L': (-1, 0, 8),
}


def solve(maze: dict) -> str:
    width, height = maze["width"], maze["height"]
    mask = maze["openMask"]
    sx, sy = maze["start"]
    ex, ey = maze["end"]

    prev = {}
    visited = [[False] * width for _ in range(height)]
    q = deque([(sx, sy)])
    visited[sy][sx] = True

    while q:
        x, y = q.popleft()
        if (x, y) == (ex, ey):
            break
        m = mask[y][x]
        for dch, (dx, dy, bit) in DIRS.items():
            if m & bit:
                nx, ny = x + dx, y + dy
                if 0 <= nx < width and 0 <= ny < height and not visited[ny][nx]:
                    visited[ny][nx] = True
                    prev[(nx, ny)] = (x, y, dch)
                    q.append((nx, ny))

    if (ex, ey) not in prev and (sx, sy) != (ex, ey):
        raise ValueError("No path found from start to end")

    path = []
    cur = (ex, ey)
    while cur != (sx, sy):
        x, y, dch = prev[cur]
        path.append(dch)
        cur = (x, y)
    path.reverse()
    return "".join(path)


def validate(maze: dict, path: str) -> bool:
    width, height = maze["width"], maze["height"]
    mask = maze["openMask"]
    x, y = maze["start"]
    for ch in path:
        dx, dy, bit = DIRS[ch]
        if not (mask[y][x] & bit):
            return False
        x, y = x + dx, y + dy
        if not (0 <= x < width and 0 <= y < height):
            return False
    return [x, y] == maze["end"]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 maze_solver.py path/to/maze.json")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        maze = json.load(f)

    path = solve(maze)
    assert validate(maze, path), "Solver produced an invalid path — this is a bug, please report it"

    print(f"Length: {len(path)}")
    print(path)
