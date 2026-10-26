def levenshtein_distance(first_term: str, second_term: str) -> int:
    if first_term == second_term:
        return 0
    if not first_term:
        return len(second_term)
    if not second_term:
        return len(first_term)

    if len(first_term) > len(second_term):
        first_term, second_term = second_term, first_term

    previous_row = list(range(len(first_term) + 1))
    for second_index, second_char in enumerate(second_term):
        current_row = [second_index + 1] + [0] * len(first_term)
        for first_index, first_char in enumerate(first_term):
            cost = 0 if first_char == second_char else 1
            current_row[first_index + 1] = min(
                current_row[first_index] + 1,
                previous_row[first_index + 1] + 1,
                previous_row[first_index] + cost,
            )
        previous_row = current_row
    return previous_row[-1]


def levenshtein_similarity(first_term: str, second_term: str) -> float:
    if first_term == second_term:
        return 1.0
    maximum_length = max(len(first_term), len(second_term))
    if maximum_length == 0:
        return 1.0
    distance = levenshtein_distance(first_term, second_term)
    return max(0.0, min(1.0, 1.0 - (distance / maximum_length)))
