import random
from typing import List, Any, Dict


def get_score(
    store: Dict[str, str],
    phone: str,
    email: str,
    birthday: Any = None,
    gender: int = None,
    first_name: str = None,
    last_name: str = None,
):
    score = 0
    if phone:
        score += 1.5
    if email:
        score += 1.5
    if birthday and gender:
        score += 1.5
    if first_name and last_name:
        score += 0.5
    return score


def get_interests(store: Dict[str, str], cid: int) -> List[str]:
    interests = [
        "cars",
        "pets",
        "travel",
        "hi-tech",
        "sport",
        "music",
        "books",
        "tv",
        "cinema",
        "geek",
        "otus",
    ]
    return random.sample(interests, 2)
