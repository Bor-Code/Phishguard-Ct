import math
from typing import Dict, Tuple

KEYBOARD_GRID: Dict[str, Tuple[float, float]] = {
    "1": (0.0, 0.0),
    "2": (0.0, 1.0),
    "3": (0.0, 2.0),
    "4": (0.0, 3.0),
    "5": (0.0, 4.0),
    "6": (0.0, 5.0),
    "7": (0.0, 6.0),
    "8": (0.0, 7.0),
    "9": (0.0, 8.0),
    "0": (0.0, 9.0),
    "-": (0.0, 10.0),
    "q": (1.0, 0.5),
    "w": (1.0, 1.5),
    "e": (1.0, 2.5),
    "r": (1.0, 3.5),
    "t": (1.0, 4.5),
    "y": (1.0, 5.5),
    "u": (1.0, 6.5),
    "i": (1.0, 7.5),
    "o": (1.0, 8.5),
    "p": (1.0, 9.5),
    "a": (2.0, 0.75),
    "s": (2.0, 1.75),
    "d": (2.0, 2.75),
    "f": (2.0, 3.75),
    "g": (2.0, 4.75),
    "h": (2.0, 5.75),
    "j": (2.0, 6.75),
    "k": (2.0, 7.75),
    "l": (2.0, 8.75),
    "z": (3.0, 1.25),
    "x": (3.0, 2.25),
    "c": (3.0, 3.25),
    "v": (3.0, 4.25),
    "b": (3.0, 5.25),
    "n": (3.0, 6.25),
    "m": (3.0, 7.25),
}


def key_distance(first_char: str, second_char: str) -> float:
    if first_char == second_char:
        return 0.0
    first_pos = KEYBOARD_GRID.get(first_char)
    second_pos = KEYBOARD_GRID.get(second_char)
    if first_pos is None or second_pos is None:
        return 1.0
    row_delta = first_pos[0] - second_pos[0]
    col_delta = first_pos[1] - second_pos[1]
    euclidean = math.sqrt(row_delta * row_delta + col_delta * col_delta)
    if euclidean <= 1.25:
        return 0.4
    if euclidean <= 1.6:
        return 0.6
    return 1.0


def keyboard_distance(first_term: str, second_term: str) -> float:
    if first_term == second_term:
        return 0.0
    if not first_term:
        return float(len(second_term))
    if not second_term:
        return float(len(first_term))

    if len(first_term) > len(second_term):
        first_term, second_term = second_term, first_term

    previous_row = [float(index) for index in range(len(first_term) + 1)]
    for second_index, second_char in enumerate(second_term):
        current_row = [float(second_index + 1)] + [0.0] * len(first_term)
        for first_index, first_char in enumerate(first_term):
            sub_cost = key_distance(first_char, second_char)
            current_row[first_index + 1] = min(
                current_row[first_index] + 1.0,
                previous_row[first_index + 1] + 1.0,
                previous_row[first_index] + sub_cost,
            )
        previous_row = current_row
    return previous_row[-1]


def keyboard_similarity(first_term: str, second_term: str) -> float:
    if first_term == second_term:
        return 1.0
    maximum_length = max(len(first_term), len(second_term))
    if maximum_length == 0:
        return 1.0
    distance = keyboard_distance(first_term, second_term)
    return max(0.0, min(1.0, 1.0 - (distance / float(maximum_length))))
