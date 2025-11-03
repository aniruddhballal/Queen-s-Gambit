"""
Chess-based encoding utilities.
Encodes binary data into chess game moves (PGN format).
"""

import random
import time
from math import log2
from chess import pgn, Board


def no_to_bin_str(num: int, bits: int):
    """
    Convert number to binary string with specified bit length.
    
    Args:
        num: int - Number to convert
        bits: int - Desired bit length
        
    Returns:
        Binary string padded with leading zeros
    """
    binary = bin(num)[2:]
    return binary.zfill(bits)


def random_user_id():
    """Generate random user ID for PGN metadata."""
    return f"{random.randint(100000, 999999)}"


def random_metadata():
    """
    Generate random chess game metadata for PGN headers.
    
    Returns:
        Dictionary of PGN metadata with some fields randomly hidden
    """
    events = [
        "Friendly Match", "Tournament", "Casual Game", "Championship", 
        "Club Championship", "Simultaneous Exhibition", "Charity Match", 
        "Blitz Tournament", "Rapid Championship", "Online Invitational"
    ]
    locations = [
        "Local Club", "Online", "City Park", "University Hall", "Community Center", 
        "Chess Cafe", "Mountain Retreat", "Coastal Town", "National Stadium", 
        "Historical Landmark"
    ]
    expected_openings = [
        "Sicilian Defense", "French Defense", "Caro-Kann", "Ruy Lopez", "Italian Game", 
        "English Opening", "King's Indian Defense", "Queen's Gambit", 
        "Nimzo-Indian Defense", "Pirc Defense", "Grünfeld Defense"
    ]
    
    # Generate the first player's rating
    white_elo = random.randint(200, 3000)
    # Calculate the range for the second player's rating
    lower_bound = int(white_elo * 0.9)
    upper_bound = int(white_elo * 1.1)
    
    # Generate the second player's rating within the specified range
    black_elo = random.randint(lower_bound, upper_bound)
    
    results = ["1-0", "0-1", "1/2-1/2", "*"]  # Possible outcomes

    metadata = {
        "Event": random.choice(events),
        "Site": random.choice(locations),
        "Date": f"{random.randint(1990, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "Round": str(random.randint(1, 15)),
        "White": random_user_id(),
        "Black": random_user_id(),
        "ExpectedOpening": random.choice(expected_openings),
        "WhiteElo": str(white_elo),
        "BlackElo": str(black_elo),
        "Result": random.choice(results),
        "Annotator": random_user_id(),
        "Variation": random.choice(["Main Line", "Alternative Line", "Quiet Move", "Aggressive Line", "Theoretical Novelty"]),
        "EventDate": f"{random.randint(1990, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "TimeControl": random.choice(["3+2", "5+0", "10+0", "15+10", "30+0", "60+0", "90+30"])
    }

    # Randomly select a number of keys to hide
    keys_to_hide = random.sample(list(metadata.keys()), random.randint(1, len(metadata) // 2))
    
    # Set the selected keys' values to "Hidden"
    for key in keys_to_hide:
        metadata[key] = "Hidden"

    return metadata


def make_gambit(sample_file: str, session_id: str = None, progress_data: dict = None):
    """
    Encode a file into chess games (PGN format).
    
    Args:
        sample_file: str - Path to file to encode
        session_id: str - Optional session ID for progress tracking
        progress_data: dict - Optional dictionary to store progress updates
        
    Returns:
        String containing PGN-formatted chess games
    """
    print("Making the Gambit...")
    bittify = (255).bit_length()

    with open(sample_file, "rb") as f:
        file01 = list(f.read())

    bits = bittify * len(file01)
    start_time = time.time()
    pgnlist = []
    current_pos = 0
    board_instance = Board()

    while True:
        # Update progress
        if session_id and progress_data is not None:
            progress_percentage = min(100, (current_pos / bits) * 100)
            elapsed_time = time.time() - start_time
            speed = current_pos / elapsed_time if elapsed_time > 0 else 0
            progress_data[session_id] = {
                'current': current_pos,
                'total': bits,
                'percentage': round(progress_percentage, 2),
                'stage': 'encoding',
                'speed': round(speed, 2),
                'elapsed_time': round(elapsed_time, 2)
            }
        
        gen_moves = board_instance.generate_legal_moves()
        moves_list = list(board_instance.generate_legal_moves())
        log_length = int(log2(len(moves_list)))
        remaining_bits = bits - current_pos
        bits_req = min(log_length, remaining_bits)

        bits_map_set_of_moves = {}
        valid_moves = {
            anti_illegal_move.uci(): no_to_bin_str(i, bits_req)
            for i, anti_illegal_move in enumerate(gen_moves)
            if len(no_to_bin_str(i, bits_req)) <= bits_req
        }

        bits_map_set_of_moves.update(valid_moves)
        next_byte_i = current_pos // bittify
        strs = ''

        for byte1 in file01[next_byte_i:next_byte_i + 2]:
            binary_string = no_to_bin_str(byte1, bittify)
            strs += binary_string

        start_index = current_pos % bittify
        next_str = ''

        for i in range(bits_req):
            if start_index + i < len(strs):
                next_str += strs[start_index + i]

        current_pos += bits_req

        for movei in bits_map_set_of_moves:
            bits_mapped = bits_map_set_of_moves[movei]
            if bits_mapped == next_str:
                board_instance.push_uci(movei)
                break
        
        if (board_instance.legal_moves.count() <= 1.5 or current_pos >= bits):
            pgn_ = pgn.Game()
            metadata = random_metadata()

            for key, value in metadata.items():
               pgn_.headers[key] = value
            
            pgn_.add_line(board_instance.move_stack)
            pgnlist.append(str(pgn_))
            board_instance.reset()

        if current_pos >= bits:
            break

    # Set progress to 100% when done
    if session_id and progress_data is not None:
        elapsed_time = time.time() - start_time
        avg_speed = bits / elapsed_time if elapsed_time > 0 else 0
        progress_data[session_id] = {
            'current': bits,
            'total': bits,
            'percentage': 100.0,
            'stage': 'encoding',
            'speed': round(avg_speed, 2),
            'elapsed_time': round(elapsed_time, 2)
        }
    
    print("Gambit done.")
    return "\n\n".join(pgnlist)